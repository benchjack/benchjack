"""
Audit control endpoints:
  POST /api/audit      — start a new audit
  POST /api/hack       — start a reward-hack run
  POST /api/rerun      — re-run from a specific phase
  POST /api/cancel     — cancel a running pipeline
"""
import asyncio
import json
import traceback
from pathlib import Path

from fastapi import APIRouter, Request

from .. import run_state
from ..ai_runner import AIRunner
from ..constants import TOOLS_DIR
from ..event_bus import EventBus
from ..pipeline import PHASES, AuditPipeline, HackPipeline, _derive_benchmark_name
from ..sandbox import Sandbox

router = APIRouter()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_HACKS_ROOT = _PROJECT_ROOT / "hacks"
_OUTPUT_ROOT = _PROJECT_ROOT / "output"


async def _run_with_error_guard(pipeline, bus: EventBus):
    """Run the pipeline and surface any unhandled exception as an error event.

    Per-phase exceptions are already caught inside the pipeline and emitted as
    ``error`` events.  This guard covers crashes that happen outside those
    handlers (e.g. in setup, resume logic, or emit calls) so the client always
    receives a visible error instead of a silent hang.
    """
    try:
        await pipeline.run()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        tb = traceback.format_exc()
        message = f"{type(exc).__name__}: {exc}\n\n{tb}"
        await bus.publish("error", {
            "phase": getattr(pipeline, "current_phase", None),
            "message": message,
        })
        await bus.publish("audit_complete", {
            "target": getattr(pipeline, "target", ""),
            "benchmark_path": getattr(pipeline, "benchmark_path", "") or "",
            "total_findings": len(getattr(pipeline, "findings", [])),
            "findings": [],
            "failed": True,
        })


def _make_run_components(backend: str | None = None, use_sandbox: bool | None = None):
    """Create a fresh sandbox + AI runner for a new pipeline run."""
    if backend is None or backend not in {"auto", "claude", "codex"}:
        backend = run_state.ai_backend
    if use_sandbox is None:
        use_sandbox = run_state.use_sandbox
    sandbox = Sandbox(str(TOOLS_DIR), enabled=use_sandbox)
    ai = AIRunner(backend=backend, model=run_state.ai_model, sandbox=sandbox)
    bus = EventBus()

    async def emit(event_type: str, data: dict):
        await bus.publish(event_type, data)

    return sandbox, ai, bus, emit


def _cleanup_old(run_id: str):
    old = run_state.active_runs.pop(run_id, None)
    if old and old["sandbox"]:
        old["sandbox"].cleanup()


@router.post("/audit")
async def start_audit(request: Request):
    body = await request.json()
    target = body.get("target", "").strip()
    backend = body.get("backend", "")
    use_sandbox = body.get("use_sandbox", None)
    poc_level = body.get("poc_level", "")
    # Backward compat: skip_poc=true maps to poc_level="skip"
    if not poc_level:
        poc_level = "skip" if body.get("skip_poc", False) else "partial"
    if poc_level not in ("full", "partial", "skip"):
        poc_level = "partial"

    if not target:
        return {"error": "target is required"}

    run_id = _derive_benchmark_name(target)

    if run_state.run_is_active(run_id):
        return {"error": f"A scan for '{target}' is already running. Cancel it first."}

    _cleanup_old(run_id)
    sandbox, ai, bus, emit = _make_run_components(backend, use_sandbox)

    pipeline = AuditPipeline(
        target=target, emit=emit, ai=ai, sandbox=sandbox,
        poc_level=poc_level,
    )
    task = asyncio.create_task(_run_with_error_guard(pipeline, bus))

    run_state.active_runs[run_id] = {
        "bus": bus, "pipeline": pipeline, "sandbox": sandbox,
        "task": task, "target": target, "mode": "audit", "backend": ai.backend,
    }
    return {"status": "started", "target": target, "run_id": run_id}


@router.post("/hack")
async def start_hack(request: Request):
    body = await request.json()
    target = body.get("target", "").strip()
    backend = body.get("backend", "")
    use_sandbox = body.get("use_sandbox", None)

    if not target:
        return {"error": "target is required"}

    run_id = "hack_" + _derive_benchmark_name(target)

    if run_state.run_is_active(run_id):
        return {"error": f"A hack run for '{target}' is already running. Cancel it first."}

    _cleanup_old(run_id)
    sandbox, ai, bus, emit = _make_run_components(backend, use_sandbox)

    pipeline = HackPipeline(target=target, emit=emit, ai=ai, sandbox=sandbox)
    task = asyncio.create_task(_run_with_error_guard(pipeline, bus))

    run_state.active_runs[run_id] = {
        "bus": bus, "pipeline": pipeline, "sandbox": sandbox,
        "task": task, "target": target, "mode": "hack", "backend": ai.backend,
    }
    return {"status": "started", "target": target, "run_id": run_id}


@router.post("/rerun")
async def rerun_from_phase(request: Request):
    body = await request.json()
    run_id = body.get("run_id", "").strip()
    from_phase = body.get("from_phase", "").strip()
    backend = body.get("backend", "")
    use_sandbox = body.get("use_sandbox", None)

    valid_phases = [pid for pid, _ in PHASES if pid != "setup"]
    if from_phase not in valid_phases:
        return {"error": f"Invalid phase '{from_phase}'. Must be one of: {valid_phases}"}

    run_entry = run_state.active_runs.get(run_id)
    if run_entry and run_state.run_is_active(run_id):
        return {"error": "The pipeline is still running. Cancel it first."}

    if run_entry:
        target = run_entry["target"]
        if not backend:
            backend = run_entry.get("backend", "")
    else:
        state_path = _HACKS_ROOT / run_id / "state.json"
        if not state_path.exists():
            return {"error": f"Run '{run_id}' not found"}
        try:
            saved = json.loads(state_path.read_text())
            target = saved.get("target", "")
            if not backend:
                backend = saved.get("backend", "")
        except (json.JSONDecodeError, OSError):
            return {"error": f"Could not read state for '{run_id}'"}
        if not target:
            return {"error": "No target found in run state"}

    # Validate that a previous run actually exists on disk.
    # The output directory is created by the pipeline only when a full run starts,
    # so its absence means the job was never run or was fully wiped.
    output_dir = _OUTPUT_ROOT / run_id
    if not output_dir.exists():
        return {
            "error": (
                f"output/{run_id} not found — "
                "need to restart the entire job."
            )
        }

    poc_level = body.get("poc_level", "partial")
    if poc_level not in ("full", "partial", "skip"):
        poc_level = "partial"

    _cleanup_old(run_id)
    sandbox, ai, bus, emit = _make_run_components(backend, use_sandbox)

    pipeline = AuditPipeline(
        target=target, emit=emit, ai=ai, sandbox=sandbox,
        rerun_from=from_phase,
        poc_level=poc_level,
    )
    task = asyncio.create_task(_run_with_error_guard(pipeline, bus))

    run_state.active_runs[run_id] = {
        "bus": bus, "pipeline": pipeline, "sandbox": sandbox,
        "task": task, "target": target, "mode": "audit", "backend": ai.backend,
    }
    return {"status": "started", "run_id": run_id, "from_phase": from_phase}


@router.post("/cancel")
async def cancel_audit(request: Request):
    body = await request.json()
    run_id = body.get("run_id", "")

    run_entry = run_state.active_runs.get(run_id)
    if not run_entry:
        return {"error": "Run not found"}

    if run_entry["pipeline"]:
        run_entry["pipeline"].cancel()
    if run_entry["task"] and not run_entry["task"].done():
        run_entry["task"].cancel()
    return {"status": "cancelled", "run_id": run_id}
