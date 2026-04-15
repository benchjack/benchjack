"""
HackPipeline — quick 2-stage reward-hacking demo.

Phases: hack → verify
"""
import json
import os
import shutil
import time
from pathlib import Path

from ..ai_runner import AIRunner
from ..sandbox import Sandbox
from .models import EXPLOIT_RESULT_JSONL, HACK_PHASES, EmitFn
from .prompts import HACK_STAGE1_PROMPT, HACK_STAGE2_PROMPT
from .utils import (
    _derive_benchmark_name,
    _expand_and_split_exploit_results,
    _read_task_ids_json,
    _read_task_results_jsonl,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class HackPipeline:
    """Quick 2-stage reward-hack pipeline (after setup)."""

    def __init__(
        self,
        target: str,
        emit: EmitFn,
        ai: AIRunner,
        sandbox: Sandbox,
    ):
        self.target = target
        self.emit = emit
        self.ai = ai
        self.sandbox = sandbox

        self.benchmark_path: str | None = None
        self._cancelled = False
        self._benchmark_name = "hack_" + _derive_benchmark_name(target)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self):
        self._ensure_dirs()

        self.benchmark_path = str(self.output_dir / "repo")
        os.makedirs(self.benchmark_path, exist_ok=True)
        self.sandbox.set_benchmark_path(self.benchmark_path)

        await self.emit("audit_start", {
            "target": self.target,
            "mode": "hack",
            "phases": [{"id": pid, "label": plabel} for pid, plabel in HACK_PHASES],
        })

        await self._emit_prior_audit_data()

        # Start the single persistent container that covers all hack phases.
        await self.sandbox.start_main_container(emit=self.emit)
        try:
            for phase_id, phase_label in HACK_PHASES:
                if self._cancelled:
                    break
                try:
                    await self._run_phase(phase_id, phase_label)
                except Exception:
                    break
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

    def _ensure_dirs(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.jacks_dir / "summary").mkdir(parents=True, exist_ok=True)
        (self.jacks_dir / "poc").mkdir(parents=True, exist_ok=True)
        self.sandbox.set_dirs(str(self.output_dir), str(self.jacks_dir))

    # ------------------------------------------------------------------
    # Prior-audit data loader
    # ------------------------------------------------------------------

    async def _emit_prior_audit_data(self):
        """Emit task IDs and task results saved by a prior audit, if available."""
        task_ids = _read_task_ids_json(str(self.jacks_dir))
        if task_ids:
            await self.emit("task_ids", {
                "task_ids": list(task_ids.keys()),
                "task_paths": task_ids,
            })
        for tr in _read_task_results_jsonl(str(self.jacks_dir)):
            await self.emit("task_result", tr)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _save_state(self, phase_id: str, status: str, duration: float):
        """Persist phase metadata to hacks/{name}/state.json."""
        state_path = self.jacks_dir / "state.json"
        state: dict = {}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        state["target"] = self.target
        state["mode"] = "hack"
        state["backend"] = self.ai.backend
        state["benchmark_name"] = self._benchmark_name
        state["benchmark_path"] = self.benchmark_path or ""
        state.setdefault("phases", {})[phase_id] = {
            "status": status,
            "duration": round(duration, 1),
            "summary": "",
        }
        state_path.write_text(json.dumps(state, indent=2) + "\n")

    def _save_log(self, phase_id: str, content: str):
        (self.output_dir / f"{phase_id}.log").write_text(content)

    def _save_summary(self, phase_id: str, content: str):
        if not content:
            return
        (self.jacks_dir / "summary" / f"{phase_id}.md").write_text(content)

    def _save_poc_scripts(self):
        if not self.benchmark_path:
            return
        src = os.path.join(self.benchmark_path, "benchjack_poc")
        if not os.path.isdir(src):
            return
        dest = self.jacks_dir / "poc"
        for f in os.listdir(src):
            if f.endswith((".py", ".sh")):
                shutil.copy2(os.path.join(src, f), dest / f)

    def _save_exploit_results(self):
        if not self.benchmark_path:
            return
        from .models import EXPLOIT_RESULT_JSONL
        src = os.path.join(self.benchmark_path, EXPLOIT_RESULT_JSONL)
        if not os.path.isfile(src):
            return
        shutil.copy2(src, self.jacks_dir / EXPLOIT_RESULT_JSONL)

    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------

    async def _run_phase(self, phase_id: str, phase_label: str):
        t0 = time.time()
        await self.emit("phase_start", {"phase": phase_id, "label": phase_label})

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
            handler = getattr(self, f"_phase_{phase_id}")
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
        self._save_poc_scripts()
        self._save_exploit_results()
        self._save_state(phase_id, status, duration)

        await self.emit("phase_complete", {
            "phase": phase_id,
            "status": status,
            "duration": round(duration, 1),
            "findings_count": 0,
        })
        if phase_id == "verify" and self.benchmark_path:
            # Task IDs come from the corresponding audit run (hacks/<name>/),
            # needed to expand any "all_tasks" entry to real task IDs.
            plain_name = self._benchmark_name.removeprefix("hack_")
            task_ids_dir = str(_PROJECT_ROOT / "hacks" / plain_name)
            task_results, exploit_list = _expand_and_split_exploit_results(
                self.benchmark_path, task_ids_dir
            )
            for tr in task_results:
                await self.emit("task_result", tr)
            if exploit_list:
                await self.emit("exploit_results", {"results": exploit_list})

    # ------------------------------------------------------------------
    # Helper: stream one AI call
    # ------------------------------------------------------------------

    async def _ai_phase(self, phase_id: str, prompt: str) -> str:
        await self.emit("log", {"phase": phase_id, "msg_type": "prompt", "text": prompt})
        text_parts: list[str] = []
        async for event in self.ai.stream(prompt):
            await self.emit("log", {"phase": phase_id, **event})
            if event.get("msg_type") == "text":
                text_parts.append(event["text"])
        return "\n".join(text_parts)

    # ------------------------------------------------------------------
    # Phase: Hack
    # ------------------------------------------------------------------

    async def _phase_hack(self):
        prompt = HACK_STAGE1_PROMPT.format(
            benchmark=self.target,
            workspace=self.sandbox.workspace,
        )
        return await self._ai_phase("hack", prompt)

    # ------------------------------------------------------------------
    # Phase: Verify & Improve
    # ------------------------------------------------------------------

    async def _phase_verify(self):
        prompt = HACK_STAGE2_PROMPT.format(
            benchmark=self.target,
            workspace=self.sandbox.workspace,
        )
        return await self._ai_phase("verify", prompt)
