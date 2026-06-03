"""
Run management endpoints:
  GET  /api/status          — active run statuses
  GET  /api/runs            — list all runs (disk + active)
  POST /api/runs/{name}/load — load a previous run into an EventBus
"""
import json
import time
from pathlib import Path

from fastapi import APIRouter

from .. import run_state
from ..event_bus import EventBus
from ..pipeline import PHASES, HACK_PHASES, clamp_refine_rounds, refine_phases
from ..pipeline.utils import _expand_and_split_exploit_results, _parse_log_events

router = APIRouter()

_HACKS_ROOT  = Path(__file__).resolve().parent.parent.parent / "hacks"
_OUTPUT_ROOT = Path(__file__).resolve().parent.parent.parent / "output"


@router.get("/status")
async def status():
    runs_status = {}
    for rid, entry in run_state.active_runs.items():
        running = entry["task"] is not None and not entry["task"].done()
        runs_status[rid] = {
            "running": running,
            "target": entry["target"],
            "mode": entry["mode"],
            "max_rounds": entry.get("max_rounds"),
        }
    return {"active_runs": runs_status}


def _phase_list(mode: str, max_rounds: int | str | None = None) -> list[str]:
    """Return the phase ID list for a given run mode."""
    if mode == "hack":
        return [pid for pid, _ in HACK_PHASES]
    if mode == "refine":
        return [pid for pid, _ in refine_phases(max_rounds)]
    return [pid for pid, _ in PHASES]


def _is_terminal_status(status: str | None) -> bool:
    return status in {"completed", "skipped"}


@router.get("/runs")
async def list_runs():
    """List all runs from hacks/ directory, plus in-memory active runs."""
    runs = []

    if _HACKS_ROOT.is_dir():
        for entry in sorted(_HACKS_ROOT.iterdir()):
            state_path = entry / "state.json"
            if not entry.is_dir() or not state_path.exists():
                continue
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            run_mode = state.get("mode", "audit")
            max_rounds = clamp_refine_rounds(state.get("max_rounds")) if run_mode == "refine" else None
            phase_ids = _phase_list(run_mode, max_rounds)
            phases = state.get("phases", {})
            completed_phases = [
                pid for pid in phase_ids
                if _is_terminal_status(phases.get(pid, {}).get("status"))
            ]
            is_finished = len(completed_phases) == len(phase_ids)
            any_failed = any(
                phases.get(pid, {}).get("status") == "failed"
                for pid in phase_ids
            )
            is_running = run_state.run_is_active(entry.name)

            if is_running:
                run_status = "running"
            elif is_finished:
                run_status = "completed"
            elif any_failed:
                run_status = "failed"
            elif completed_phases:
                run_status = "incomplete"
            else:
                run_status = "empty"

            total_duration = sum(
                phases.get(pid, {}).get("duration", 0) for pid in phase_ids
            )

            findings_count = 0
            findings_path = entry / "findings.json"
            if findings_path.exists():
                try:
                    findings_count = len(json.loads(findings_path.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    pass

            runs.append({
                "name": entry.name,
                "target": state.get("target", entry.name),
                "mode": run_mode,
                "backend": state.get("backend", ""),
                "max_rounds": max_rounds,
                "status": run_status,
                "completed_phases": completed_phases,
                "total_phases": len(phase_ids),
                "total_duration": round(total_duration, 1),
                "findings_count": findings_count,
                "mtime": state_path.stat().st_mtime,
                "phases": {pid: phases.get(pid, {}) for pid in phase_ids},
            })

    # Include active runs not yet on disk
    for rid, entry in run_state.active_runs.items():
        if any(r["name"] == rid for r in runs):
            continue
        if entry["task"] and not entry["task"].done():
            entry_mode = entry.get("mode", "audit")
            max_rounds = entry.get("max_rounds") if entry_mode == "refine" else None
            runs.append({
                "name": rid,
                "target": entry["target"],
                "mode": entry_mode,
                "backend": entry.get("backend", ""),
                "max_rounds": max_rounds,
                "status": "running",
                "completed_phases": [],
                "total_phases": len(_phase_list(entry_mode, max_rounds)),
                "total_duration": 0,
                "findings_count": 0,
                "mtime": time.time(),
                "phases": {},
            })

    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return {"runs": runs}


@router.post("/runs/{name}/load")
async def load_run(name: str):
    """Load a previous run's state into an EventBus for viewing."""
    if run_state.run_is_active(name):
        return {"error": "This run is currently active. View it directly."}

    state_path = _HACKS_ROOT / name / "state.json"
    if not state_path.exists():
        return {"error": f"Run '{name}' not found"}

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"error": f"Could not read state for '{name}'"}

    bus = EventBus()
    target = state.get("target", name)
    run_mode = state.get("mode", "audit")
    run_backend = state.get("backend", "")
    max_rounds = clamp_refine_rounds(state.get("max_rounds")) if run_mode == "refine" else None
    phases_meta = state.get("phases", {})

    phase_list = (HACK_PHASES if run_mode == "hack"
                  else refine_phases(max_rounds) if run_mode == "refine"
                  else PHASES)
    await bus.publish("audit_start", {
        "target": target,
        "mode": run_mode,
        "backend": run_backend,
        "max_rounds": max_rounds,
        "restore": True,
        "phases": [{"id": pid, "label": plabel} for pid, plabel in phase_list],
    })

    # Load findings
    findings = []
    findings_path = _HACKS_ROOT / name / "findings.json"
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    # Load task results
    task_results = []
    tr_path = _HACKS_ROOT / name / "task_results.json"
    if tr_path.exists():
        try:
            task_results = json.loads(tr_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    # Load task IDs enumerated during recon (new: dict {id: path}, legacy: list)
    task_ids: list[str] = []
    task_paths: dict[str, str] = {}
    tid_path = _HACKS_ROOT / name / "task_ids.json"
    if tid_path.exists():
        try:
            loaded = json.loads(tid_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                task_paths = {str(k): str(v) for k, v in loaded.items()}
                task_ids = list(task_paths.keys())
            elif isinstance(loaded, list):
                task_ids = [str(x) for x in loaded]
        except (json.JSONDecodeError, OSError):
            pass

    # Replay each completed phase (use the mode-appropriate phase list)
    for phase_id, phase_label in phase_list:
        meta = phases_meta.get(phase_id, {})
        phase_status = meta.get("status")
        if not phase_status or phase_status == "pending":
            continue

        await bus.publish("phase_start", {"phase": phase_id, "label": phase_label})

        # -- Output view: replay individual log events from the .log file.
        # Fallback to the summary text if no log file exists (e.g. hack runs).
        log_path = _OUTPUT_ROOT / name / f"{phase_id}.log"
        summary_path = _HACKS_ROOT / name / "summary" / f"{phase_id}.md"
        summary_text = ""
        try:
            summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
        except OSError:
            pass

        if log_path.exists():
            try:
                log_content = log_path.read_text(encoding="utf-8")
                for log_data in _parse_log_events(log_content, phase_id):
                    await bus.publish("log", log_data)
            except OSError:
                pass
        elif summary_text.strip():
            # No log file — show summary as plain text in the output view
            await bus.publish("log", {
                "phase": phase_id,
                "msg_type": "text",
                "text": summary_text,
            })

        # -- Summary view: emit the .md content as a dedicated event so it
        # populates the summary pane without duplicating in the output view.
        if summary_text.strip():
            await bus.publish("phase_summary", {
                "phase": phase_id,
                "text": summary_text,
            })

        if phase_id == "recon" and task_ids:
            await bus.publish("task_ids", {
                "task_ids": task_ids,
                "task_paths": task_paths,
            })

        if phase_id == "vuln_scan":
            for f in findings:
                await bus.publish("finding", f)

        if phase_id in ("vuln_scan", "poc"):
            for tr in task_results:
                await bus.publish("task_result", tr)

        if phase_id in ("poc", "verify") or (
            run_mode == "refine" and phase_id.endswith("_attack")
        ):
            run_dir = str(_HACKS_ROOT / name)
            # For hack/refine runs, task IDs live in the corresponding audit dir.
            if run_mode == "hack":
                task_ids_dir = str(_HACKS_ROOT / name.removeprefix("hack_"))
            elif run_mode == "refine":
                task_ids_dir = str(_HACKS_ROOT / name.removeprefix("refine_"))
            else:
                task_ids_dir = run_dir
            task_results, exploit_list = _expand_and_split_exploit_results(
                run_dir, task_ids_dir
            )
            for tr in task_results:
                await bus.publish("task_result", tr)
            if exploit_list:
                await bus.publish("exploit_results", {"results": exploit_list})

        await bus.publish("phase_complete", {
            "phase": phase_id,
            "status": phase_status,
            "duration": meta.get("duration", 0),
            "findings_count": len(findings) if phase_id == "vuln_scan" else 0,
            "summary": meta.get("summary", ""),
        })

    all_completed = all(
        _is_terminal_status(phases_meta.get(pid, {}).get("status"))
        for pid, _ in phase_list
    )

    if run_mode == "refine" and all_completed:
        await bus.publish("refine_complete", {
            "converged": any(
                phases_meta.get(pid, {}).get("status") == "skipped"
                for pid, _ in phase_list
            ),
            "final_hack_rate": state.get("final_hack_rate"),
            "max_rounds": max_rounds,
        })

    await bus.publish("audit_complete", {
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
        "failed": False,
        "loaded_from_history": True,
    })

    run_state.active_runs[name] = {
        "bus": bus,
        "pipeline": None,
        "sandbox": None,
        "task": None,
        "target": target,
        "mode": run_mode,
        "backend": run_backend,
        "max_rounds": max_rounds,
    }

    return {
        "status": "loaded",
        "target": target,
        "finished": all_completed,
        "run_id": name,
    }
