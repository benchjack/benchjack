"""
AuditPipeline — 5-phase benchmark hackability auditor.

Phases: setup → recon → vuln_scan → poc → report
"""
import asyncio
import json
import os
import shutil
import time
from dataclasses import asdict
from pathlib import Path

from ..ai_runner import AIRunner
from ..sandbox import Sandbox
from .models import (
    EXPLOIT_RESULT_JSONL,
    PHASES,
    TASK_IDS_JSON,
    TASK_RESULTS_JSONL,
    EmitFn,
    Finding,
    PhaseResult,
)
from .prompts import (
    POC_GENERATE_PROMPT,
    POC_VALIDATE_PROMPT,
    RECON_PROMPT,
    REPORT_PROMPT,
    SEARCH_PROMPT,
    VULN_SCAN_JSONL_RETRY_PROMPT,
    VULN_SCAN_PROMPT,
    _poc_scope_blocks,
    _validate_scope_blocks,
)
from .utils import (
    _derive_benchmark_name,
    _expand_and_split_exploit_results,
    _extract_findings,
    _parse_log_events,
    _read_task_ids_json,
    _read_task_results_jsonl,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class AuditPipeline:

    def __init__(
        self,
        target: str,
        emit: EmitFn,
        ai: AIRunner,
        sandbox: Sandbox,
        *,
        rerun_from: str | None = None,
        poc_level: str = "partial",  # "full" | "partial" | "skip"
    ):
        self.target = target
        self.emit = emit
        self.ai = ai
        self.sandbox = sandbox
        self.rerun_from = rerun_from
        self.poc_level = poc_level if poc_level in ("full", "partial", "skip") else "partial"

        self.benchmark_path: str | None = None
        self.results: dict[str, PhaseResult] = {}
        self.findings: list[Finding] = []
        self._cancelled = False
        self._benchmark_name = _derive_benchmark_name(target)
        self._task_results: list[dict] = []
        self._task_ids: dict[str, str] = {}  # id → file path

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self):
        # Validate restart: the output directory must already exist on disk
        if self.rerun_from and not self.output_dir.exists():
            raise RuntimeError(
                f"output/{self._benchmark_name} not found — "
                "restart the entire job to begin fresh."
            )

        self._ensure_dirs()
        completed = self._try_resume()

        await self.emit("audit_start", {
            "target": self.target,
            "mode": "audit",
            "phases": [{"id": pid, "label": plabel} for pid, plabel in PHASES],
        })

        if completed:
            label = f"Resuming from previous run (completed: {', '.join(sorted(completed))})"
            if self.rerun_from:
                label += f" — re-running from {self.rerun_from}"
            await self.emit("log", {
                "phase": "setup", "msg_type": "text",
                "text": label,
            })

        failed = False
        try:
            for phase_id, phase_label in PHASES:
                if self._cancelled:
                    break
                if phase_id in completed:
                    await self._emit_resumed_phase(phase_id, phase_label)
                    if phase_id == "setup":
                        # Setup was already done in a prior run; start the
                        # persistent container now so post-setup phases use it.
                        await self.sandbox.start_main_container(emit=self.emit)
                    continue
                if phase_id == "poc" and self.poc_level == "skip":
                    await self.emit("phase_skip", {"phase": phase_id})
                    continue
                try:
                    await self._run_phase(phase_id, phase_label)
                    if phase_id == "setup":
                        # Setup just completed; start the persistent container.
                        await self.sandbox.start_main_container(emit=self.emit)
                except Exception:
                    failed = True
                    break
        finally:
            await self.sandbox.stop_main_container()

        await self.emit("audit_complete", {
            "target": self.target,
            "benchmark_path": self.benchmark_path,
            "total_findings": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
            "failed": failed,
        })

    def cancel(self):
        self._cancelled = True

    # ------------------------------------------------------------------
    # Persistence: directories
    # ------------------------------------------------------------------

    @property
    def output_dir(self) -> Path:
        return _PROJECT_ROOT / "output" / self._benchmark_name

    @property
    def jacks_dir(self) -> Path:
        return _PROJECT_ROOT / "hacks" / self._benchmark_name

    def _ensure_dirs(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.jacks_dir / "summary").mkdir(parents=True, exist_ok=True)
        (self.jacks_dir / "poc").mkdir(parents=True, exist_ok=True)
        self.sandbox.set_dirs(str(self.output_dir), str(self.jacks_dir))

    # ------------------------------------------------------------------
    # Persistence: save helpers
    # ------------------------------------------------------------------

    def _save_log(self, phase_id: str, content: str):
        (self.output_dir / f"{phase_id}.log").write_text(content)

    def _save_summary(self, phase_id: str, content: str):
        if not content:
            return
        (self.jacks_dir / "summary" / f"{phase_id}.md").write_text(content)

    def _save_state(self, phase_id: str, result: PhaseResult):
        """Update hacks/state.json with this phase's metadata."""
        state_path = self.jacks_dir / "state.json"
        state: dict = {}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        state["target"] = self.target
        state["mode"] = "audit"
        state["backend"] = self.ai.backend
        state["benchmark_name"] = self._benchmark_name
        state["benchmark_path"] = self.benchmark_path or ""
        state.setdefault("phases", {})[phase_id] = {
            "status": result.status,
            "duration": round(result.duration, 1),
            "summary": result.summary,
        }
        state_path.write_text(json.dumps(state, indent=2) + "\n")

    def _save_findings(self):
        path = self.jacks_dir / "findings.json"
        path.write_text(json.dumps([asdict(f) for f in self.findings], indent=2) + "\n")

    def _save_task_results(self):
        if not self._task_results:
            return
        path = self.jacks_dir / "task_results.json"
        path.write_text(json.dumps(self._task_results, indent=2) + "\n")

    def _save_task_ids(self):
        if not self._task_ids:
            return
        path = self.jacks_dir / "task_ids.json"
        path.write_text(json.dumps(self._task_ids, indent=2) + "\n")  # dict {id: path}

    def _save_poc_scripts(self):
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, "benchjack_poc")
        if not os.path.isdir(src):
            return
        dest = self.jacks_dir / "poc"
        for f in os.listdir(src):
            if f.endswith(".py") or f.endswith(".sh"):
                shutil.copy2(os.path.join(src, f), dest / f)

    def _save_exploit_results(self):
        if not self.benchmark_path:
            return
        from .models import EXPLOIT_RESULT_JSONL
        src = os.path.join(self.benchmark_path, EXPLOIT_RESULT_JSONL)
        if not os.path.isfile(src):
            return
        shutil.copy2(src, self.jacks_dir / EXPLOIT_RESULT_JSONL)

    def _save_raw_task_ids(self):
        """Copy benchjack_task_ids.json from workspace into hacks/{name}/."""
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, TASK_IDS_JSON)
        if not os.path.isfile(src):
            return
        shutil.copy2(src, self.jacks_dir / TASK_IDS_JSON)

    def _save_raw_task_results(self):
        """Copy benchjack_task_results.jsonl from workspace into hacks/{name}/."""
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, TASK_RESULTS_JSONL)
        if not os.path.isfile(src):
            return
        shutil.copy2(src, self.jacks_dir / TASK_RESULTS_JSONL)

    # ------------------------------------------------------------------
    # Persistence: resume from previous run
    # ------------------------------------------------------------------

    def _try_resume(self) -> set[str]:
        """Load completed phases from a previous run. Returns the set of
        phase IDs that were successfully restored. If ``rerun_from`` is set,
        phases from that point onward are treated as incomplete so they re-run."""
        completed: set[str] = set()
        state_path = self.jacks_dir / "state.json"
        if not state_path.exists():
            return completed

        try:
            state = json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError):
            return completed

        phases_meta = state.get("phases", {})

        phase_ids = [pid for pid, _ in PHASES]
        invalidated: set[str] = set()
        if self.rerun_from and self.rerun_from in phase_ids:
            idx = phase_ids.index(self.rerun_from)
            invalidated = set(phase_ids[idx:])

        bp = state.get("benchmark_path", "")
        if bp and os.path.isdir(bp):
            self.benchmark_path = bp
            self.sandbox.set_benchmark_path(bp)

        if "setup" in phases_meta and phases_meta["setup"].get("status") == "completed":
            if self.benchmark_path:
                self.results["setup"] = PhaseResult(
                    phase="setup",
                    status="completed",
                    duration=phases_meta["setup"].get("duration", 0),
                    summary=phases_meta["setup"].get("summary", ""),
                )
                completed.add("setup")

        if "setup" not in completed:
            return completed

        findings_path = self.jacks_dir / "findings.json"
        if findings_path.exists():
            try:
                for obj in json.loads(findings_path.read_text()):
                    self.findings.append(Finding(**obj))
            except (json.JSONDecodeError, OSError, TypeError):
                pass

        tr_path = self.jacks_dir / "task_results.json"
        if tr_path.exists():
            try:
                self._task_results = json.loads(tr_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        tid_path = self.jacks_dir / "task_ids.json"
        if tid_path.exists():
            try:
                loaded = json.loads(tid_path.read_text())
                if isinstance(loaded, dict):
                    self._task_ids = {str(k): str(v) for k, v in loaded.items()}
                elif isinstance(loaded, list):
                    self._task_ids = {str(x): "" for x in loaded}
            except (json.JSONDecodeError, OSError):
                pass

        for phase_id, _ in PHASES:
            if phase_id == "setup":
                continue
            if phase_id in invalidated:
                break
            meta = phases_meta.get(phase_id, {})
            if meta.get("status") != "completed":
                break
            summary_path = self.jacks_dir / "summary" / f"{phase_id}.md"
            if not summary_path.exists():
                break
            self.results[phase_id] = PhaseResult(
                phase=phase_id,
                status="completed",
                output=summary_path.read_text(),
                duration=meta.get("duration", 0),
                summary=meta.get("summary", ""),
                findings=list(self.findings) if phase_id == "vuln_scan" else [],
            )
            completed.add(phase_id)

        if "vuln_scan" in invalidated:
            self.findings.clear()
            self._task_results.clear()
        elif "poc" in invalidated:
            self._task_results.clear()

        return completed

    async def _emit_resumed_phase(self, phase_id: str, phase_label: str):
        """Replay events for a phase loaded from a previous run."""
        await self.emit("phase_start", {"phase": phase_id, "label": phase_label})

        r = self.results.get(phase_id, PhaseResult(phase=phase_id))

        # Output view: parse the saved .log file into individual events.
        # Fall back to the summary text if the log is missing.
        log_path = self.output_dir / f"{phase_id}.log"
        if log_path.exists():
            log_content = log_path.read_text()
            for log_data in _parse_log_events(log_content, phase_id):
                await self.emit("log", log_data)
        elif r.output:
            await self.emit("log", {
                "phase": phase_id, "msg_type": "text",
                "text": r.output,
            })
        else:
            await self.emit("log", {
                "phase": phase_id, "msg_type": "text",
                "text": "[Loaded from previous run]",
            })

        # Summary view: emit the .md file as a dedicated phase_summary event.
        summary_path = self.jacks_dir / "summary" / f"{phase_id}.md"
        if summary_path.exists():
            summary_text = summary_path.read_text()
            if summary_text.strip():
                await self.emit("phase_summary", {"phase": phase_id, "text": summary_text})
        elif r.output:
            await self.emit("phase_summary", {"phase": phase_id, "text": r.output})

        if phase_id == "recon" and self._task_ids:
            await self.emit("task_ids", {
                "task_ids": list(self._task_ids.keys()),
                "task_paths": self._task_ids,
            })

        if phase_id == "vuln_scan":
            for f in self.findings:
                await self.emit("finding", asdict(f))

        if phase_id in ("vuln_scan", "poc") and self._task_results:
            for tr in self._task_results:
                await self.emit("task_result", tr)

        if phase_id == "poc":
            _, exploit_list = _expand_and_split_exploit_results(
                str(self.jacks_dir), str(self.jacks_dir)
            )
            if exploit_list:
                await self.emit("exploit_results", {"results": exploit_list})

        await self.emit("phase_complete", {
            "phase": phase_id,
            "status": "completed",
            "duration": round(r.duration, 1),
            "findings_count": len(r.findings),
            "summary": r.summary or "",
        })

    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------

    async def _run_phase(self, phase_id: str, phase_label: str):
        t0 = time.time()
        await self.emit("phase_start", {"phase": phase_id, "label": phase_label})
        result = PhaseResult(phase=phase_id, status="running")

        # Wrap emit to capture log lines and task results
        log_lines: list[str] = []
        original_emit = self.emit

        async def capturing_emit(event_type, data):
            await original_emit(event_type, data)
            if event_type == "log":
                mt = data.get("msg_type", "text")
                if mt == "text":
                    log_lines.append(data.get("text", ""))
                elif mt == "prompt":
                    log_lines.append(f"[prompt]\n{data.get('text', '')}\n[/prompt]")
                elif mt == "tool_call":
                    log_lines.append(
                        f"[tool: {data.get('name', '?')}] {data.get('summary', '')}"
                    )
                elif mt == "tool_result":
                    log_lines.append(f"[result: {data.get('chars', 0)} chars]")
            elif event_type == "task_result":
                self._task_results.append(dict(data))

        self.emit = capturing_emit
        try:
            handler = getattr(self, f"_phase_{phase_id}")
            await handler(result)
            result.status = "completed"
        except Exception as exc:
            result.status = "failed"
            result.summary = str(exc)
            result.duration = time.time() - t0
            self.results[phase_id] = result
            self.emit = original_emit
            self._save_log(phase_id, "\n".join(log_lines))
            await self.emit("error", {"phase": phase_id, "message": str(exc)})
            await self.emit("phase_complete", {
                "phase": phase_id,
                "status": "failed",
                "duration": round(result.duration, 1),
                "findings_count": 0,
                "summary": result.summary,
            })
            raise

        self.emit = original_emit
        result.duration = time.time() - t0
        self.results[phase_id] = result

        self._save_log(phase_id, "\n".join(log_lines))
        self._save_summary(phase_id, result.output)
        self._save_state(phase_id, result)
        if phase_id == "vuln_scan":
            self._save_findings()
        if phase_id in ("vuln_scan", "poc"):
            self._save_task_results()
        if phase_id == "recon":
            self._save_task_ids()
            self._save_raw_task_ids()
        if phase_id == "vuln_scan":
            self._save_raw_task_results()
        if phase_id == "poc":
            self._save_poc_scripts()
            self._save_exploit_results()

        await self.emit("phase_complete", {
            "phase": phase_id,
            "status": result.status,
            "duration": round(result.duration, 1),
            "findings_count": len(result.findings),
            "summary": result.summary,
        })
        if phase_id == "poc" and self.benchmark_path:
            _, exploit_list = _expand_and_split_exploit_results(
                self.benchmark_path, self.benchmark_path
            )
            if exploit_list:
                await self.emit("exploit_results", {"results": exploit_list})

    # ------------------------------------------------------------------
    # Helper: stream one AI call and collect output
    # ------------------------------------------------------------------

    async def _ai_phase(self, phase_id: str, prompt: str) -> str:
        """Run a single AI call, stream its output, return the full text."""
        await self.emit("log", {"phase": phase_id, "msg_type": "prompt", "text": prompt})
        text_parts: list[str] = []
        async for event in self.ai.stream(prompt):
            await self.emit("log", {"phase": phase_id, **event})
            if event.get("msg_type") == "text":
                text_parts.append(event["text"])
        return "\n".join(text_parts)

    # ------------------------------------------------------------------
    # Phase 1: Setup
    # ------------------------------------------------------------------

    async def _phase_setup(self, result: PhaseResult):
        target = self.target.strip()

        if os.path.isdir(target):
            self.benchmark_path = os.path.abspath(target)
            await self.emit("log", {
                "phase": "setup",
                "msg_type": "text",
                "text": f"Using local path: {self.benchmark_path}",
            })

        elif target.startswith(("http://", "https://")):
            self.benchmark_path = await self._git_clone(target)

        elif "/" in target:
            url = f"https://github.com/{target}"
            await self.emit("log", {"phase": "setup", "msg_type": "text", "text": f"Trying {url} …"})
            self.benchmark_path = await self._git_clone(url)

        else:
            repo_dir = str(self.output_dir / "repo")
            os.makedirs(repo_dir, exist_ok=True)
            if os.listdir(repo_dir):
                self.benchmark_path = repo_dir
                await self.emit("log", {
                    "phase": "setup", "msg_type": "text",
                    "text": f"Using previously cloned repo at {repo_dir}",
                })
            else:
                await self.emit("log", {
                    "phase": "setup", "msg_type": "text",
                    "text": f"Searching for benchmark '{target}' …",
                })
                self.sandbox.set_benchmark_path(repo_dir)
                # Run the search+clone on the host to avoid Docker
                # Desktop volume-mount issues (gRPC-FUSE/VirtioFS on
                # macOS can fail to write to freshly bind-mounted dirs).
                # URL/path targets already clone on the host, so this
                # keeps the setup phase consistent.
                sandbox_was_enabled = self.sandbox.enabled
                self.sandbox.enabled = False
                try:
                    prompt = SEARCH_PROMPT.format(
                        name=target, dest=self.sandbox.workspace,
                    )
                    await self._ai_phase("setup", prompt)
                finally:
                    self.sandbox.enabled = sandbox_was_enabled

                if any(os.scandir(repo_dir)):
                    self.benchmark_path = repo_dir
                else:
                    raise RuntimeError(
                        f"Could not locate benchmark '{target}'. "
                        "Provide a local path, URL, or owner/repo slug."
                    )

        self.sandbox.set_benchmark_path(self.benchmark_path)
        result.summary = f"Benchmark at {self.benchmark_path}"

    async def _git_clone(self, url: str) -> str:
        dest = str(self.output_dir / "repo")
        os.makedirs(dest, exist_ok=True)
        if os.listdir(dest):
            await self.emit("log", {
                "phase": "setup", "msg_type": "text",
                "text": f"Using previously cloned repo at {dest}",
            })
            return dest
        await self.emit("log", {"phase": "setup", "msg_type": "text", "text": f"Cloning {url} …"})
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", url, dest,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed:\n{stderr.decode()}")
        await self.emit("log", {"phase": "setup", "msg_type": "text", "text": f"Cloned to {dest}"})
        return dest

    # ------------------------------------------------------------------
    # Phase 2: Reconnaissance
    # ------------------------------------------------------------------

    async def _phase_recon(self, result: PhaseResult):
        hadolint_line = (
            f"  bash {{tools}}/run_hadolint.sh {{workspace}}".format(
                tools=self.sandbox.tools_mount,
                workspace=self.sandbox.workspace,
            )
            if self.sandbox.hadolint_available else ""
        )
        prompt = RECON_PROMPT.format(
            workspace=self.sandbox.workspace,
            tools=self.sandbox.tools_mount,
            task_ids_filename=TASK_IDS_JSON,
            hadolint_line=hadolint_line,
        )
        result.output = await self._ai_phase("recon", prompt)
        result.summary = "Reconnaissance complete"

        task_ids = _read_task_ids_json(self.benchmark_path)
        if task_ids:
            self._task_ids = task_ids
            await self.emit("task_ids", {
                "task_ids": list(task_ids.keys()),
                "task_paths": task_ids,
            })

    # ------------------------------------------------------------------
    # Phase 3: Vulnerability Scan
    # ------------------------------------------------------------------

    async def _phase_vuln_scan(self, result: PhaseResult):
        recon_output = self.results.get("recon", PhaseResult(phase="recon")).output
        hadolint_line = (
            f"  bash {{tools}}/run_hadolint.sh {{workspace}}".format(
                tools=self.sandbox.tools_mount,
                workspace=self.sandbox.workspace,
            )
            if self.sandbox.hadolint_available else ""
        )
        prompt = VULN_SCAN_PROMPT.format(
            workspace=self.sandbox.workspace,
            tools=self.sandbox.tools_mount,
            recon_output=recon_output[:12000],
            hadolint_line=hadolint_line,
        )
        full = await self._ai_phase("vuln_scan", prompt)
        result.output = full

        for f in _extract_findings(full):
            result.findings.append(f)
            self.findings.append(f)
            await self.emit("finding", asdict(f))

        jsonl_path = os.path.join(self.benchmark_path, TASK_RESULTS_JSONL)
        if not os.path.isfile(jsonl_path):
            await self.emit("log", {
                "phase": "vuln_scan",
                "msg_type": "text",
                "text": f"{TASK_RESULTS_JSONL} not found — starting follow-up session to generate it.",
            })
            retry_prompt = VULN_SCAN_JSONL_RETRY_PROMPT.format(
                workspace=self.sandbox.workspace,
                jsonl_filename=TASK_RESULTS_JSONL,
                vuln_output=full[:12000],
            )
            retry_full = await self._ai_phase("vuln_scan", retry_prompt)
            result.output = full + "\n\n---\n\n" + retry_full

        for tr in _read_task_results_jsonl(self.benchmark_path):
            await self.emit("task_result", tr)

        result.summary = f"{len(result.findings)} finding(s)"

    # ------------------------------------------------------------------
    # Phase 4: PoC Construction
    # ------------------------------------------------------------------

    async def _phase_poc(self, result: PhaseResult):
        vuln_output = self.results.get("vuln_scan", PhaseResult(phase="vuln_scan")).output
        recon_output = self.results.get("recon", PhaseResult(phase="recon")).output
        findings_json = json.dumps([asdict(f) for f in self.findings], indent=2)

        run_scope, run_scope_note = _poc_scope_blocks(self.poc_level)
        validate_scope_intro, validate_scope_check = _validate_scope_blocks(self.poc_level)

        gen_prompt = POC_GENERATE_PROMPT.format(
            workspace=self.sandbox.workspace,
            tools=self.sandbox.tools_mount,
            recon_output=recon_output[:10000],
            vuln_output=vuln_output[:12000],
            findings_json=findings_json[:6000],
            run_scope=run_scope,
            run_scope_note=run_scope_note,
        )
        gen_output = await self._ai_phase("poc", gen_prompt)

        validate_prompt = POC_VALIDATE_PROMPT.format(
            workspace=self.sandbox.workspace,
            recon_output=recon_output[:10000],
            validate_scope_intro=validate_scope_intro,
            validate_scope_check=validate_scope_check,
        )
        validate_output = await self._ai_phase("poc", validate_prompt)

        task_results, _ = _expand_and_split_exploit_results(
            self.benchmark_path, self.benchmark_path
        )
        for tr in task_results:
            await self.emit("task_result", tr)

        result.output = gen_output + "\n\n---\n\n" + validate_output
        result.summary = "PoC scripts generated and validated"

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Phase 5: Report
    # ------------------------------------------------------------------

    async def _phase_report(self, result: PhaseResult):
        findings_json = json.dumps([asdict(f) for f in self.findings], indent=2)
        prompt = REPORT_PROMPT.format(
            target=self.target,
            workspace=self.sandbox.workspace,
            findings_json=findings_json,
            recon_output=self.results.get("recon", PhaseResult(phase="recon")).output[:8000],
            vuln_output=self.results.get("vuln_scan", PhaseResult(phase="vuln_scan")).output[:8000],
        )
        result.output = await self._ai_phase("report", prompt)
        result.summary = "Report generated"
