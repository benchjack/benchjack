"""Tests for server.sandbox.Sandbox — path logic and disabled mode.

These tests run with sandbox.enabled=False to avoid Docker dependency.
"""

import os

import pytest

from server import sandbox as sandbox_module
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
        # set_benchmark_path normalises via os.path.abspath — on Windows
        # "/some/bench" becomes "C:\some\bench", so compare after abspath.
        assert sandbox.workspace == os.path.abspath("/some/bench")

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


@pytest.mark.asyncio
async def test_main_container_places_user_args_before_image(tmp_path, monkeypatch):
    """Docker options must appear before IMAGE_TAG, not in the container command."""
    tools = tmp_path / "tools"
    tools.mkdir()
    home = tmp_path / "home"
    home.mkdir()

    sb = Sandbox(str(tools), enabled=False)
    sb.enabled = True
    sb.set_benchmark_path(str(tmp_path / "benchmark"))
    sb.set_dirs(str(tmp_path / "output"), str(tmp_path / "hacks"))

    async def fake_ensure_image(_self, emit=None):
        return None

    monkeypatch.setattr(Sandbox, "ensure_image", fake_ensure_image)
    monkeypatch.setattr(sb, "_prepare_claude_dir", lambda: setattr(sb, "_claude_dir", str(home)))
    monkeypatch.setattr(sandbox_module, "_docker_user_args", lambda: ["--user", "1000:1000"])

    captured = {}

    async def fake_create_subprocess_exec(*args, **_kwargs):
        captured["args"] = list(args)

        class FakeProc:
            returncode = 0

            async def communicate(self):
                return b"abc123\n", b""

        return FakeProc()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    await sb.start_main_container()
    sb._container_id = None
    sb.cleanup()

    args = captured["args"]
    image_index = args.index(sandbox_module.IMAGE_TAG)
    user_index = args.index("--user")
    assert user_index < image_index
    assert args[image_index + 1:image_index + 3] == ["sleep", "infinity"]


def test_ephemeral_ai_mounts_registered_evidence_directories(tmp_path, monkeypatch):
    sb = Sandbox(str(tmp_path), enabled=False)
    sb.set_dirs(str(tmp_path / "output"), str(tmp_path / "hacks"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(sb, "_prepare_claude_dir", lambda: None)
    sb._claude_dir = str(tmp_path / "home")
    args = sb._base_docker_args(network=True, ai=True)
    mounts = [args[i + 1] for i, value in enumerate(args) if value == "-v"]
    assert str(tmp_path / "hacks") + ":/hacks" in mounts
    assert str(tmp_path / "output") + ":/output" in mounts
