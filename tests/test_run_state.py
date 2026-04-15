"""Tests for server.run_state."""

from unittest.mock import MagicMock

import pytest

from server import run_state


@pytest.fixture(autouse=True)
def _clean():
    run_state.active_runs.clear()
    yield
    run_state.active_runs.clear()


class TestRunState:
    def test_get_run_exists(self):
        run_state.active_runs["abc"] = {"task": None, "target": "x"}
        assert run_state.get_run("abc") is not None

    def test_get_run_missing(self):
        assert run_state.get_run("nonexistent") is None

    def test_run_is_active_no_entry(self):
        assert run_state.run_is_active("nope") is False

    def test_run_is_active_no_task(self):
        run_state.active_runs["x"] = {"task": None}
        assert run_state.run_is_active("x") is False

    def test_run_is_active_done_task(self):
        task = MagicMock()
        task.done.return_value = True
        run_state.active_runs["x"] = {"task": task}
        assert run_state.run_is_active("x") is False

    def test_run_is_active_running_task(self):
        task = MagicMock()
        task.done.return_value = False
        run_state.active_runs["x"] = {"task": task}
        assert run_state.run_is_active("x") is True
