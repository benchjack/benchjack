"""Focused regression tests for the iterative refinement pipeline."""

import json

import pytest

from server.pipeline import refine as refine_module
from server.pipeline.refine import RefinePipeline
from server.sandbox import Sandbox


class FakeAI:
    backend = "fake"

    async def stream(self, _prompt):
        yield {"msg_type": "text", "text": "no working exploit found"}


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
