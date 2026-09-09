"""Tests for the FastAPI API endpoints.

Uses httpx + FastAPI TestClient with mocked pipeline/AI dependencies.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.app import create_app
from server import run_state
from server.routes import runs as runs_module


@pytest.fixture(autouse=True)
def _clean_run_state():
    """Reset global run state between tests."""
    run_state.active_runs.clear()
    run_state.ai_backend = "auto"
    run_state.ai_model = None
    run_state.use_sandbox = False
    yield
    run_state.active_runs.clear()


@pytest.fixture
def client():
    app = create_app(ai_backend="claude", sandbox=False)
    return TestClient(app)


class TestStatusEndpoint:
    def test_status_empty(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.json()["active_runs"] == {}

    def test_status_with_active_run(self, client):
        task = MagicMock()
        task.done.return_value = False
        run_state.active_runs["test_run"] = {
            "bus": None, "pipeline": None, "sandbox": None,
            "task": task, "target": "my/bench", "mode": "audit",
        }
        resp = client.get("/api/status")
        data = resp.json()
        assert "test_run" in data["active_runs"]
        assert data["active_runs"]["test_run"]["target"] == "my/bench"


class TestRunsEndpoint:
    def test_runs_empty(self, client):
        resp = client.get("/api/runs")
        assert resp.status_code == 200
        assert isinstance(resp.json()["runs"], list)

    def test_refine_skipped_phases_count_as_finished(self, client, tmp_path, monkeypatch):
        hacks_root = tmp_path / "hacks"
        run_dir = hacks_root / "refine_demo"
        run_dir.mkdir(parents=True)
        state = {
            "target": "demo",
            "mode": "refine",
            "backend": "fake",
            "max_rounds": 3,
            "phases": {
                "r1_attack": {"status": "completed", "duration": 1.0},
                "r1_patch": {"status": "skipped", "duration": 0.0},
                "r2_attack": {"status": "skipped", "duration": 0.0},
                "r2_patch": {"status": "skipped", "duration": 0.0},
                "r3_attack": {"status": "skipped", "duration": 0.0},
            },
        }
        (run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        monkeypatch.setattr(runs_module, "_HACKS_ROOT", hacks_root)
        monkeypatch.setattr(runs_module, "_OUTPUT_ROOT", tmp_path / "output")

        resp = client.get("/api/runs")
        run = resp.json()["runs"][0]

        assert run["status"] == "completed"
        assert run["completed_phases"] == [
            "r1_attack", "r1_patch", "r2_attack", "r2_patch", "r3_attack",
        ]
        assert run["total_phases"] == 5

    def test_load_refine_skipped_phases_is_finished(self, client, tmp_path, monkeypatch):
        hacks_root = tmp_path / "hacks"
        run_dir = hacks_root / "refine_demo"
        run_dir.mkdir(parents=True)
        state = {
            "target": "demo",
            "mode": "refine",
            "backend": "fake",
            "max_rounds": 2,
            "phases": {
                "r1_attack": {"status": "completed", "duration": 1.0},
                "r1_patch": {"status": "skipped", "duration": 0.0},
                "r2_attack": {"status": "skipped", "duration": 0.0},
            },
        }
        (run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        monkeypatch.setattr(runs_module, "_HACKS_ROOT", hacks_root)
        monkeypatch.setattr(runs_module, "_OUTPUT_ROOT", tmp_path / "output")

        resp = client.post("/api/runs/refine_demo/load")

        assert resp.json()["finished"] is True
        history = run_state.active_runs["refine_demo"]["bus"]._history
        assert any(
            event["type"] == "refine_complete"
            and event["data"]["converged"] is True
            for event in history
        )


class TestAuditEndpoint:
    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_audit_missing_target(self, mock_sandbox, mock_ai, client):
        resp = client.post("/api/audit", json={"target": ""})
        assert resp.json()["error"] == "target is required"

    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_audit_starts(self, mock_sandbox, mock_ai, client):
        mock_ai_instance = MagicMock()
        mock_ai_instance.backend = "claude"
        mock_ai.return_value = mock_ai_instance
        mock_sb_instance = MagicMock()
        mock_sandbox.return_value = mock_sb_instance

        with patch("server.routes.audit.AuditPipeline") as mock_pipeline:
            mock_pipeline_instance = AsyncMock()
            mock_pipeline.return_value = mock_pipeline_instance

            resp = client.post("/api/audit", json={"target": "org/bench"})
            data = resp.json()
            assert data["status"] == "started"
            assert data["target"] == "org/bench"
            assert "run_id" in data

    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_audit_poc_level_default(self, mock_sandbox, mock_ai, client):
        mock_ai_instance = MagicMock()
        mock_ai_instance.backend = "claude"
        mock_ai.return_value = mock_ai_instance
        mock_sandbox.return_value = MagicMock()

        with patch("server.routes.audit.AuditPipeline") as mock_pipeline:
            mock_pipeline.return_value = AsyncMock()
            client.post("/api/audit", json={"target": "org/bench"})
            _, kwargs = mock_pipeline.call_args
            assert kwargs["poc_level"] == "partial"

    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_audit_skip_poc_backward_compat(self, mock_sandbox, mock_ai, client):
        mock_ai_instance = MagicMock()
        mock_ai_instance.backend = "claude"
        mock_ai.return_value = mock_ai_instance
        mock_sandbox.return_value = MagicMock()

        with patch("server.routes.audit.AuditPipeline") as mock_pipeline:
            mock_pipeline.return_value = AsyncMock()
            client.post("/api/audit", json={"target": "org/bench", "skip_poc": True})
            _, kwargs = mock_pipeline.call_args
            assert kwargs["poc_level"] == "skip"


class TestHackEndpoint:
    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_hack_missing_target(self, mock_sandbox, mock_ai, client):
        resp = client.post("/api/hack", json={"target": ""})
        assert resp.json()["error"] == "target is required"


class TestRefineEndpoint:
    @patch("server.routes.audit.AIRunner")
    @patch("server.routes.audit.Sandbox")
    def test_refine_passes_custom_round_count(self, mock_sandbox, mock_ai, client):
        mock_ai_instance = MagicMock()
        mock_ai_instance.backend = "claude"
        mock_ai.return_value = mock_ai_instance
        mock_sandbox.return_value = MagicMock()

        with patch("server.routes.audit.RefinePipeline") as mock_pipeline:
            mock_pipeline.return_value = AsyncMock()
            resp = client.post("/api/refine", json={
                "target": "org/bench",
                "max_rounds": 5,
            })
            data = resp.json()
            assert data["status"] == "started"
            assert data["max_rounds"] == 5
            _, kwargs = mock_pipeline.call_args
            assert kwargs["max_rounds"] == 5
            assert run_state.active_runs[data["run_id"]]["max_rounds"] == 5

    def test_refine_rejects_invalid_round_count(self, client):
        resp = client.post("/api/refine", json={
            "target": "org/bench",
            "max_rounds": 11,
        })
        assert resp.json()["error"] == "max_rounds must be between 1 and 10"


class TestCancelEndpoint:
    def test_cancel_unknown_run(self, client):
        resp = client.post("/api/cancel", json={"run_id": "nonexistent"})
        assert resp.json()["error"] == "Run not found"


class TestRerunEndpoint:
    def test_rerun_invalid_phase(self, client):
        resp = client.post("/api/rerun", json={
            "run_id": "test", "from_phase": "setup"
        })
        assert "Invalid phase" in resp.json()["error"]

    def test_rerun_valid_phases(self, client):
        # Valid non-setup phases
        for phase in ("recon", "vuln_scan", "poc", "report"):
            resp = client.post("/api/rerun", json={
                "run_id": "nonexistent", "from_phase": phase
            })
            # Should fail because run not found, not because phase is invalid
            assert "Invalid phase" not in resp.json().get("error", "")
