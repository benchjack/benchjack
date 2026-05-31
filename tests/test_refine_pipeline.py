"""Focused regression tests for the iterative refinement pipeline."""

import json
from pathlib import Path

import pytest

from server.pipeline import refine as refine_module
from server.pipeline.refine import RefinePipeline
from server.sandbox import Sandbox


class FakeAI:
    backend = "fake"

    async def stream(self, _prompt, cwd=None):
        yield {"msg_type": "text", "text": "no working exploit found"}


class LoopAI:
    backend = "fake"

    def __init__(self):
        self.verify_calls = 0
        self.cwd_seen = []

    async def stream(self, prompt, cwd=None):
        self.cwd_seen.append(cwd)
        repo = Path(cwd)
        if "reward hacking verifier" in prompt:
            self.verify_calls += 1
            exploit_path = repo / "exploit_result.jsonl"
            if self.verify_calls == 1:
                exploit_path.write_text(json.dumps({
                    "task": "demo_task",
                    "vulnerability": "V6",
                    "severity": "CRITICAL",
                    "hacked": True,
                    "explanation": "debug bypass",
                }) + "\n")
                (repo / "benchjack_poc").mkdir(exist_ok=True)
                (repo / "benchjack_poc" / "run.sh").write_text("#!/bin/sh\n")
                yield {"msg_type": "text", "text": "verified exploit"}
            else:
                exploit_path.write_text("")
                yield {"msg_type": "text", "text": "no exploit remains"}
        elif "benchmark security hardener" in prompt:
            (repo / "evaluate.py").write_text("print('patched')\n")
            yield {"msg_type": "text", "text": "patched evaluator"}
        else:
            yield {"msg_type": "text", "text": "prepared exploit"}


class FailingAI:
    backend = "fake"

    async def stream(self, _prompt, cwd=None):
        if False:
            yield {}
        raise RuntimeError("backend exploded")


class AlwaysHackAI:
    backend = "fake"

    async def stream(self, prompt, cwd=None):
        repo = Path(cwd)
        if "reward hacking verifier" in prompt:
            (repo / "exploit_result.jsonl").write_text(json.dumps({
                "task": "demo_task",
                "vulnerability": "V7",
                "severity": "CRITICAL",
                "hacked": True,
                "explanation": "still hackable",
            }) + "\n")
            (repo / "benchjack_poc").mkdir(exist_ok=True)
            (repo / "benchjack_poc" / "run.sh").write_text("#!/bin/sh\n")
            yield {"msg_type": "text", "text": "verified exploit"}
        elif "benchmark security hardener" in prompt:
            yield {"msg_type": "text", "text": "patched"}
        else:
            yield {"msg_type": "text", "text": "prepared exploit"}


@pytest.mark.asyncio
async def test_refine_converges_when_attack_writes_no_exploit_rows(tmp_path, monkeypatch):
    """No successful exploit rows means zero hacked tasks, not unknown progress."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    prior_audit_dir = tmp_path / "hacks" / "sample-bench"
    prior_audit_dir.mkdir(parents=True)
    (prior_audit_dir / "benchjack_task_ids.json").write_text(json.dumps({
        "task_1": "tasks/1.json",
        "task_2": "tasks/2.json",
        "task_3": "tasks/3.json",
    }))

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline("sample-bench", emit, FakeAI(), sandbox)

    await pipeline.run()

    round_events = [
        data for event_type, data in events
        if event_type == "refine_round_complete"
    ]
    assert round_events == [{
        "round": 1,
        "hack_rate": 0.0,
        "hacked": 0,
        "total": 3,
        "converged": True,
    }]
    started_phases = [
        data["phase"] for event_type, data in events
        if event_type == "phase_start"
    ]
    assert "r1_patch" not in started_phases


@pytest.mark.asyncio
async def test_refine_runs_patch_then_converges_on_next_attack(tmp_path, monkeypatch):
    """A hacked first round should patch, re-attack, then converge on no rows."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    benchmark = tmp_path / "benchmark"
    benchmark.mkdir()
    (benchmark / "README.md").write_text("demo benchmark\n")
    (benchmark / "evaluate.py").write_text("print('vulnerable')\n")

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    ai = LoopAI()
    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline(str(benchmark), emit, ai, sandbox)

    await pipeline.run()

    started_phases = [
        data["phase"] for event_type, data in events
        if event_type == "phase_start"
    ]
    assert started_phases == ["r1_attack", "r1_patch", "r2_attack"]

    round_events = [
        data for event_type, data in events
        if event_type == "refine_round_complete"
    ]
    assert round_events == [
        {
            "round": 1,
            "hack_rate": 1.0,
            "hacked": 1,
            "total": 1,
            "converged": False,
        },
        {
            "round": 2,
            "hack_rate": 0.0,
            "hacked": 0,
            "total": 1,
            "converged": True,
        },
    ]
    assert all(cwd == pipeline.benchmark_path for cwd in ai.cwd_seen)
    assert (Path(pipeline.benchmark_path) / "evaluate.py").read_text() == "print('patched')\n"


@pytest.mark.asyncio
async def test_refine_custom_round_count_runs_extra_round(tmp_path, monkeypatch):
    """Custom round caps should add attack/patch phases beyond the default 3."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    benchmark = tmp_path / "benchmark"
    benchmark.mkdir()
    (benchmark / "README.md").write_text("demo benchmark\n")

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline(str(benchmark), emit, AlwaysHackAI(), sandbox, max_rounds=4)

    await pipeline.run()

    started_phases = [
        data["phase"] for event_type, data in events
        if event_type == "phase_start"
    ]
    assert started_phases == [
        "r1_attack", "r1_patch",
        "r2_attack", "r2_patch",
        "r3_attack", "r3_patch",
        "r4_attack",
    ]
    complete_events = [
        data for event_type, data in events
        if event_type == "refine_complete"
    ]
    assert complete_events == [{
        "converged": False,
        "final_hack_rate": 1.0,
        "max_rounds": 4,
    }]
    state = json.loads((tmp_path / "hacks" / "refine_benchmark" / "state.json").read_text())
    assert state["max_rounds"] == 4
    assert state["phases"]["r4_attack"]["status"] == "completed"
    assert "r4_patch" not in state["phases"]


@pytest.mark.asyncio
async def test_refine_phase_failure_is_marked_and_raised(tmp_path, monkeypatch):
    """Backend failures must not turn into silent incomplete refine runs."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline("sample-bench", emit, FailingAI(), sandbox)

    with pytest.raises(RuntimeError, match="backend exploded"):
        await pipeline.run()

    assert ("error", {"phase": "r1_attack", "message": "backend exploded"}) in events
    state = json.loads((tmp_path / "hacks" / "refine_sample-bench" / "state.json").read_text())
    assert state["phases"]["r1_attack"]["status"] == "failed"


def test_refine_reset_workspace_retries_permission_error(tmp_path, monkeypatch):
    """Windows can briefly deny deleting cloned Git pack files."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline("sample-bench", emit, FakeAI(), sandbox)
    dest = pipeline.output_dir / "repo"
    dest.mkdir(parents=True)
    (dest / "old.txt").write_text("old\n")

    real_rmtree = refine_module.shutil.rmtree
    calls = {"count": 0}

    def flaky_rmtree(path, onerror=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise PermissionError("locked")
        return real_rmtree(path, onerror=onerror)

    monkeypatch.setattr(refine_module.shutil, "rmtree", flaky_rmtree)

    pipeline._reset_workspace(dest)

    assert calls["count"] == 2
    assert dest.exists()
    assert not (dest / "old.txt").exists()


@pytest.mark.asyncio
async def test_refine_phase_marks_running_at_start(tmp_path, monkeypatch):
    """Reruns should not show a stale failed phase while work is active."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline("sample-bench", emit, FakeAI(), sandbox)
    pipeline._ensure_dirs()
    pipeline.benchmark_path = str(pipeline.output_dir / "repo")
    pipeline._save_state("r1_attack", "failed", 10.0)

    async def handler():
        state = json.loads((pipeline.jacks_dir / "state.json").read_text())
        assert state["phases"]["r1_attack"]["status"] == "running"
        return "done"

    await pipeline._run_phase("r1_attack", "Round 1 - Attack", handler)


def test_refine_remove_readonly_unlinks_inaccessible_symlink(tmp_path):
    """ProgramBench can leave WSL venv links that Windows cannot scan."""
    link = tmp_path / "lib64"
    try:
        refine_module.os.symlink(tmp_path / "missing", link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")

    def inaccessible(_path):
        raise OSError("cannot scan")

    RefinePipeline._handle_remove_readonly(inaccessible, str(link), None)

    assert not refine_module.os.path.lexists(link)


def test_refine_remove_readonly_removes_inaccessible_directory(tmp_path):
    """Windows reports WSL-created junctions as inaccessible directories."""
    path = tmp_path / "lib64"
    path.mkdir()

    def inaccessible(_path):
        raise OSError("cannot scan")

    RefinePipeline._handle_remove_readonly(inaccessible, str(path), None)

    assert not path.exists()


def test_refine_persists_unicode_logs_and_summaries(tmp_path, monkeypatch):
    """Claude output can contain symbols that fail with Windows cp1252 defaults."""
    monkeypatch.setattr(refine_module, "_PROJECT_ROOT", tmp_path)

    async def emit(_event_type, _data):
        pass

    sandbox = Sandbox(str(tmp_path / "tools"), enabled=False)
    pipeline = RefinePipeline("sample-bench", emit, FakeAI(), sandbox)
    pipeline._ensure_dirs()

    text = "verified \u2705 solved"
    pipeline._save_log("r1_attack", text)
    pipeline._save_summary("r1_attack", text)

    assert (pipeline.output_dir / "r1_attack.log").read_text(encoding="utf-8") == text
    assert (pipeline.jacks_dir / "summary" / "r1_attack.md").read_text(encoding="utf-8") == text
