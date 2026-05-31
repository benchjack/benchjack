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
