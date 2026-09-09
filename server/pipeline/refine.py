"""
RefinePipeline — iterative attacker/defender loop (Section 4.3).

Phases: rN_attack, with rN_patch after every non-final attack round.
The default cap is 3 rounds, but callers may configure a larger bounded cap.
Early exit: if hack_rate == 0 after any attack round, remaining rounds are
skipped and convergence is declared.
"""
import asyncio
import json
import os
import shutil
import stat
import time
from pathlib import Path

from ..ai_runner import AIRunner
from ..sandbox import Sandbox
from .models import EXPLOIT_RESULT_JSONL, EmitFn, clamp_refine_rounds, refine_phases
from .prompts import HACK_STAGE1_PROMPT, HACK_STAGE2_PROMPT, PATCH_PROMPT
from .utils import (
    _derive_benchmark_name,
    _expand_and_split_exploit_results,
    _read_task_ids_json,
    _read_task_results_jsonl,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class RefinePipeline:
    """GAN-inspired iterative attacker/defender loop."""

    def __init__(
        self,
        target: str,
        emit: EmitFn,
        ai: AIRunner,
        sandbox: Sandbox,
        *,
        max_rounds: int = 3,
    ):
        self.target = target
        self.emit = emit
        self.ai = ai
        self.sandbox = sandbox
        self.max_rounds = clamp_refine_rounds(max_rounds)

        self.benchmark_path: str | None = None
        self._cancelled = False
        self._benchmark_name = "refine_" + _derive_benchmark_name(target)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self):
        self._ensure_dirs()

        self.benchmark_path = str(self.output_dir / "repo")
        self.sandbox.set_benchmark_path(self.benchmark_path)

        await self.emit("audit_start", {
            "target": self.target,
            "mode": "refine",
            "max_rounds": self.max_rounds,
            "phases": [{"id": pid, "label": plabel} for pid, plabel in refine_phases(self.max_rounds)],
        })

        await self._prepare_workspace()
        await self.sandbox.start_main_container(emit=self.emit)
        try:
            await self._run_loop()
        finally:
            await self.sandbox.stop_main_container()

        await self.emit("audit_complete", {
            "target": self.target,
            "benchmark_path": self.benchmark_path,
            "jacks_dir": str(self.jacks_dir),
            "total_findings": 0,
            "findings": [],
            "failed": False,
        })

    def cancel(self):
        self._cancelled = True

    # ------------------------------------------------------------------
    # Directories
    # ------------------------------------------------------------------

    @property
    def output_dir(self) -> Path:
        return _PROJECT_ROOT / "output" / self._benchmark_name

    @property
    def jacks_dir(self) -> Path:
        return _PROJECT_ROOT / "hacks" / self._benchmark_name

    def round_dir(self, n: int) -> Path:
        return self.jacks_dir / f"r{n}"

    def _ensure_dirs(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.jacks_dir / "summary").mkdir(parents=True, exist_ok=True)
        for n in range(1, self.max_rounds + 1):
            (self.jacks_dir / f"r{n}").mkdir(parents=True, exist_ok=True)
        self.sandbox.set_dirs(str(self.output_dir), str(self.jacks_dir))

    async def _prepare_workspace(self):
        """Create a clean benchmark workspace for this refine run."""
        if not self.benchmark_path:
            return

        dest = Path(self.benchmark_path)
        self._reset_workspace(dest)

        target = self.target.strip()
        if os.path.isdir(target):
            self._copy_local_target(Path(target), dest)
        elif target.startswith(("http://", "https://")):
            await self._git_clone(target, dest)
        elif "/" in target:
            await self._git_clone(f"https://github.com/{target}", dest)
        else:
            # Keep an empty workspace for named benchmarks. The attack prompt
            # still asks the AI backend to locate and clone the benchmark.
            dest.mkdir(parents=True, exist_ok=True)

        self.sandbox.set_benchmark_path(str(dest))

    def _reset_workspace(self, dest: Path):
        output_dir = self.output_dir.resolve()
        parent = dest.parent.resolve()
        if parent != output_dir:
            raise RuntimeError(f"Refusing to reset unexpected workspace: {dest}")
        if dest.exists():
            for attempt in range(3):
                try:
                    shutil.rmtree(dest, onerror=self._handle_remove_readonly)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    time.sleep(0.5)
        dest.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _handle_remove_readonly(func, path, exc_info):
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(path)
        except OSError:
            if Path(path).is_symlink():
                os.unlink(path)
                return
            if os.path.lexists(path):
                try:
                    os.rmdir(path)
                except OSError:
                    os.unlink(path)
                return
            raise

    def _copy_local_target(self, src: Path, dest: Path):
        src_resolved = src.resolve()
        dest_resolved = dest.resolve()
        if src_resolved == dest_resolved or dest_resolved.is_relative_to(src_resolved):
            raise RuntimeError(
                f"Refusing to copy benchmark into itself: {src_resolved} -> {dest_resolved}"
            )
        shutil.copytree(src_resolved, dest_resolved, dirs_exist_ok=True)

    async def _git_clone(self, url: str, dest: Path):
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", url, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            details = stderr.decode(errors="replace") or stdout.decode(errors="replace")
            raise RuntimeError(f"git clone failed for {url}:\n{details}")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _run_loop(self):
        converged = False
        last_hack_rate: float | None = None

        for round_n in range(1, self.max_rounds + 1):
            if self._cancelled:
                break

            # --- Attack phase ---
            attack_id = f"r{round_n}_attack"
            attack_label = f"Round {round_n} — Attack"
            await self._run_phase(
                attack_id, attack_label,
                lambda rn=round_n: self._phase_attack(rn),
                round_n=round_n,
            )

            if self._cancelled:
                break

            # --- Compute hack rate ---
            hack_rate, hacked, total = self._compute_hack_rate()
            last_hack_rate = hack_rate

            # --- Convergence check ---
            if total > 0 and hack_rate == 0.0:
                converged = True
                await self.emit("refine_round_complete", {
                    "round": round_n,
                    "hack_rate": 0.0,
                    "hacked": 0,
                    "total": total,
                    "converged": True,
                })
                # Skip current round's patch (if not the last round)
                if round_n < self.max_rounds:
                    await self._skip_phase(f"r{round_n}_patch", "converged")
                # Skip all remaining rounds
                for remaining in range(round_n + 1, self.max_rounds + 1):
                    await self._skip_phase(f"r{remaining}_attack", "converged")
                    if remaining < self.max_rounds:
                        await self._skip_phase(f"r{remaining}_patch", "converged")
                break

            # --- Patch phase (no patch after the final attack round) ---
            if round_n < self.max_rounds:
                patch_id = f"r{round_n}_patch"
                patch_label = f"Round {round_n} — Patch"
                await self._run_phase(
                    patch_id, patch_label,
                    lambda rn=round_n: self._phase_patch(rn),
                    round_n=round_n,
                )

            # --- Emit round complete ---
            await self.emit("refine_round_complete", {
                "round": round_n,
                "hack_rate": round(hack_rate, 3),
                "hacked": hacked,
                "total": total,
                "converged": False,
            })

        await self.emit("refine_complete", {
            "converged": converged,
            "final_hack_rate": round(last_hack_rate, 3) if last_hack_rate is not None else None,
            "max_rounds": self.max_rounds,
        })

    # ------------------------------------------------------------------
    # Hack-rate computation
    # ------------------------------------------------------------------

    def _compute_hack_rate(self) -> tuple[float, int, int]:
        """Read exploit_result.jsonl from workspace and return (rate, hacked, total).

        Handles the ``"all_tasks"`` sentinel: looks up the real task count from
        a prior audit run in ``hacks/<plain_name>/`` and expands accordingly.
        """
        if not self.benchmark_path:
            return 0.0, 0, 0

        results = self._read_verified_results()
        known_total = self._known_task_total(fallback=None)
        if not results:
            return 0.0, 0, known_total or 1

        # Detect "all_tasks" sentinel
        has_all_tasks = any(r["task"] == "all_tasks" for r in results)
        if has_all_tasks:
            total = known_total or 1
            all_hacked = any(
                r["task"] == "all_tasks" and r.get("hacked") for r in results
            )
            if all_hacked:
                return 1.0, total, total
            return 0.0, 0, total

        result_tasks = {
            r["task"] for r in results
            if r.get("task") and r.get("task") != "all_tasks"
        }
        total = known_total or len(result_tasks)
        if total == 0:
            return 0.0, 0, 0
        hacked_tasks = {
            r["task"] for r in results
            if r.get("task") and r.get("hacked")
        }
        hacked = min(len(hacked_tasks), total)
        return hacked / total, hacked, total

    def _read_verified_results(self) -> list[dict]:
        """Require a complete JSONL artifact, including an explicit empty result."""
        path = Path(self.benchmark_path) / EXPLOIT_RESULT_JSONL
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(f"Verification results are missing or unreadable: {path}") from exc
        results = []
        for line_number, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid verification result on line {line_number}") from exc
            if (not isinstance(row, dict)
                    or not isinstance(row.get("task"), str)
                    or not row["task"].strip()
                    or not isinstance(row.get("hacked"), bool)):
                raise RuntimeError(f"Invalid verification result on line {line_number}")
            results.append({**row, "task": row["task"].strip()})
        return results

    def _known_task_total(self, *, fallback: int | None = 1) -> int | None:
        """Return the known task count, or fallback when unavailable."""
        if self.benchmark_path:
            task_ids = _read_task_ids_json(self.benchmark_path)
            if task_ids and "all_tasks" not in task_ids:
                return len(task_ids)

        plain_name = self._benchmark_name.removeprefix("refine_")
        task_ids_dir = str(_PROJECT_ROOT / "hacks" / plain_name)
        task_ids = _read_task_ids_json(task_ids_dir)
        if task_ids and "all_tasks" not in task_ids:
            return len(task_ids)
        return fallback

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _skip_phase(self, phase_id: str, reason: str):
        self._save_state(phase_id, "skipped", 0.0)
        await self.emit("phase_skip", {
            "phase": phase_id,
            "reason": reason,
        })

    def _save_state(self, phase_id: str, status: str, duration: float):
        state_path = self.jacks_dir / "state.json"
        state: dict = {}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        state["target"] = self.target
        state["mode"] = "refine"
        state["backend"] = self.ai.backend
        state["benchmark_name"] = self._benchmark_name
        state["benchmark_path"] = self.benchmark_path or ""
        state["max_rounds"] = self.max_rounds
        state.setdefault("phases", {})[phase_id] = {
            "status": status,
            "duration": round(duration, 1),
            "summary": "",
        }
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    def _save_log(self, phase_id: str, content: str):
        (self.output_dir / f"{phase_id}.log").write_text(content, encoding="utf-8")

    def _save_summary(self, phase_id: str, content: str):
        if not content:
            return
        (self.jacks_dir / "summary" / f"{phase_id}.md").write_text(content, encoding="utf-8")

    def _save_poc_scripts(self, round_n: int):
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, "benchjack_poc")
        if not os.path.isdir(src):
            return
        dest = self.round_dir(round_n)
        for f in os.listdir(src):
            if f.endswith((".py", ".sh")):
                shutil.copy2(os.path.join(src, f), dest / f)

    def _save_exploit_results(self, round_n: int):
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, EXPLOIT_RESULT_JSONL)
        if not os.path.isfile(src):
            return
        shutil.copy2(src, self.round_dir(round_n) / EXPLOIT_RESULT_JSONL)

    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------

    async def _run_phase(self, phase_id: str, phase_label: str, handler, *, round_n: int = 1):
        t0 = time.time()
        await self.emit("phase_start", {"phase": phase_id, "label": phase_label})
        self._save_state(phase_id, "running", 0.0)

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
                    log_lines.append(f"[tool: {data.get('name', '?')}] {data.get('summary', '')}")
                elif mt == "tool_result":
                    log_lines.append(f"[result: {data.get('chars', 0)} chars]")

        self.emit = capturing_emit
        try:
            output = await handler()
            status = "completed"
        except Exception as exc:
            duration = time.time() - t0
            self.emit = original_emit
            self._save_log(phase_id, "\n".join(log_lines))
            self._save_state(phase_id, "failed", duration)
            await self.emit("error", {"phase": phase_id, "message": str(exc)})
            await self.emit("phase_complete", {
                "phase": phase_id,
                "status": "failed",
                "duration": round(duration, 1),
                "findings_count": 0,
            })
            raise

        self.emit = original_emit
        duration = time.time() - t0
        self._save_log(phase_id, "\n".join(log_lines))
        self._save_summary(phase_id, output or "")

        if phase_id.endswith("_attack"):
            self._save_poc_scripts(round_n)
            self._save_exploit_results(round_n)

        self._save_state(phase_id, status, duration)

        await self.emit("phase_complete", {
            "phase": phase_id,
            "status": status,
            "duration": round(duration, 1),
            "findings_count": 0,
        })

        # After an attack phase: push task/exploit data to the scoreboard
        if phase_id.endswith("_attack") and self.benchmark_path:
            await self._emit_attack_results(phase_id)

    async def _emit_attack_results(self, phase_id: str):
        """Best-effort UI replay; persistence already succeeded by this point."""
        try:
            plain_name = self._benchmark_name.removeprefix("refine_")
            task_ids_dir = str(_PROJECT_ROOT / "hacks" / plain_name)
            task_results, exploit_list = _expand_and_split_exploit_results(
                self.benchmark_path or "", task_ids_dir
            )
            for tr in task_results:
                await self.emit("task_result", tr)
            if exploit_list:
                await self.emit("exploit_results", {"results": exploit_list})
        except Exception as exc:
            await self.emit("log", {
                "phase": phase_id,
                "msg_type": "text",
                "text": f"[warning] Could not load exploit results for scoreboard: {exc}",
            })

    # ------------------------------------------------------------------
    # Helper: stream one AI call
    # ------------------------------------------------------------------

    async def _ai_phase(self, phase_id: str, prompt: str) -> str:
        await self.emit("log", {"phase": phase_id, "msg_type": "prompt", "text": prompt})
        text_parts: list[str] = []
        cwd = self.sandbox.workspace if self.sandbox.enabled else self.benchmark_path
        async for event in self.ai.stream(prompt, cwd=cwd):
            await self.emit("log", {"phase": phase_id, **event})
            if event.get("msg_type") == "text":
                text_parts.append(event["text"])
        return "\n".join(text_parts)

    # ------------------------------------------------------------------
    # Phase: Attack
    # ------------------------------------------------------------------

    async def _phase_attack(self, round_n: int) -> str:
        phase_id = f"r{round_n}_attack"
        prompt1 = HACK_STAGE1_PROMPT.format(
            benchmark=self.target,
            workspace=self.sandbox.workspace,
        )
        await self._ai_phase(phase_id, prompt1)

        prompt2 = HACK_STAGE2_PROMPT.format(
            benchmark=self.target,
            workspace=self.sandbox.workspace,
        )
        # The verifier must produce its own result, not reuse an earlier attack.
        (Path(self.benchmark_path) / EXPLOIT_RESULT_JSONL).unlink(missing_ok=True)
        prompt2 += (
            "\nOnly write verification results after evaluation has completed. "
            "If setup or evaluation cannot complete, report the failure and leave "
            "the result file absent. An empty file means evaluation completed "
            "and confirmed no successful exploits.\n"
        )
        output = await self._ai_phase(phase_id, prompt2)
        self._read_verified_results()
        return output

    # ------------------------------------------------------------------
    # Phase: Patch
    # ------------------------------------------------------------------

    async def _phase_patch(self, round_n: int) -> str:
        phase_id = f"r{round_n}_patch"
        if self.sandbox.enabled:
            exploit_path = f"/hacks/r{round_n}/{EXPLOIT_RESULT_JSONL}"
            findings_path = f"/hacks/summary/r{round_n}_attack.md"
        else:
            exploit_path = str(self.round_dir(round_n) / EXPLOIT_RESULT_JSONL)
            findings_path = str(self.jacks_dir / "summary" / f"r{round_n}_attack.md")
        prompt = PATCH_PROMPT.format(
            workspace=self.sandbox.workspace,
            exploit_path=exploit_path,
            findings_path=findings_path,
        )
        return await self._ai_phase(phase_id, prompt)
