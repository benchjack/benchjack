"""Tests for server.sandbox.Sandbox — path logic and disabled mode.

These tests run with sandbox.enabled=False to avoid Docker dependency.
"""

import os

import pytest

from server.sandbox import Sandbox


@pytest.fixture
def sandbox(tmp_path):
    """A Sandbox with Docker disabled."""
    tools = tmp_path / "tools"
    tools.mkdir()
    sb = Sandbox(str(tools), enabled=False)
    yield sb
    sb.cleanup()


class TestSandboxPaths:
    def test_workspace_disabled(self, sandbox):
        sandbox.set_benchmark_path("/some/bench")
        assert sandbox.workspace == "/some/bench"

    def test_tools_mount_disabled(self, sandbox):
        assert sandbox.tools_mount == sandbox.tools_dir

    def test_results_dir_is_temp(self, sandbox):
        assert os.path.isdir(sandbox.results_dir)

    def test_result_file_missing(self, sandbox):
        assert sandbox.result_file("nonexistent.json") is None

    def test_result_file_exists(self, sandbox):
        p = os.path.join(sandbox.results_dir, "output.json")
        with open(p, "w") as f:
            f.write("{}")
        assert sandbox.result_file("output.json") == p

    def test_set_dirs(self, sandbox, tmp_path):
        out = tmp_path / "output"
        hacks = tmp_path / "hacks"
        out.mkdir()
        hacks.mkdir()
        sandbox.set_dirs(str(out), str(hacks))
        assert sandbox._output_dir == str(out)
        assert sandbox._jacks_dir == str(hacks)


class TestSandboxCleanup:
    def test_cleanup_removes_results_dir(self, tmp_path):
        tools = tmp_path / "tools"
        tools.mkdir()
        sb = Sandbox(str(tools), enabled=False)
        results_dir = sb.results_dir
        assert os.path.isdir(results_dir)
        sb.cleanup()
        assert not os.path.isdir(results_dir)

    def test_double_cleanup_safe(self, tmp_path):
        tools = tmp_path / "tools"
        tools.mkdir()
        sb = Sandbox(str(tools), enabled=False)
        sb.cleanup()
        sb.cleanup()  # should not raise
