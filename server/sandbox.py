"""
Docker-based sandbox for running static-analysis tools and AI CLIs
in isolation from the host.

Two container profiles:
  static  – --network=none, no credentials (for semgrep, bandit, …)
  ai      – default bridge network, API keys forwarded (for claude/codex)

Container lifecycle:
  setup phase   → short-lived ``docker run --rm`` container; only the repo
                  directory (output/$BENCHMARK/repo/) is mounted as /workspace
  later phases  → ONE persistent ``docker run -d`` container started after setup
                  with /workspace, /output, /hacks all mounted; each AI call
                  runs via ``docker exec`` into that container so auth and
                  filesystem state survive across phases
  restart       → ``start_main_container()`` is called again on a fresh Sandbox,
                  mounting the same on-disk directories

When Docker is not available the sandbox falls back transparently to
direct subprocess execution on the host.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import AsyncGenerator

log = logging.getLogger("benchjack.sandbox")

IMAGE_NAME = "benchjack-sandbox"
IMAGE_TAG = f"{IMAGE_NAME}:latest"
DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile.sandbox"


def _extract_claude_credentials() -> dict | None:
    """Extract the full Claude Code credentials JSON from the macOS Keychain.

    Returns the parsed credentials dict, or None if unavailable.
    The dict typically contains a ``claudeAiOauth`` key with OAuth tokens.
    """
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", "Claude Code-credentials", "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout.strip())
    except Exception:
        return None


class Sandbox:
    """Docker sandbox for benchmark analysis.

    Parameters
    ----------
    tools_dir : str
        Absolute path to the BenchJack static-analysis tools on the host.
    enabled : bool
        If False, every method runs directly on the host (no Docker).
    """

    def __init__(self, tools_dir: str, *, enabled: bool = True):
        self.tools_dir = os.path.abspath(tools_dir)
        self.benchmark_path: str | None = None
        self.enabled = enabled and self._docker_ok()
        self._image_ready = False
        self._results_dir = tempfile.mkdtemp(prefix="benchjack_results_")
        self._claude_dir: str | None = None   # writable copy of ~/.claude
        self._container_id: str | None = None  # persistent post-setup container
        self._output_dir: str | None = None    # host path → /output in container
        self._jacks_dir: str | None = None     # host path → /hacks in container

    # ------------------------------------------------------------------
    # Path helpers — container vs. host
    # ------------------------------------------------------------------

    @property
    def hadolint_available(self) -> bool:
        """True if hadolint can be invoked (built into image when sandboxed)."""
        if self.enabled:
            return True  # installed in Dockerfile.sandbox
        return shutil.which("hadolint") is not None

    def set_benchmark_path(self, path: str):
        """Set after the setup phase discovers / clones the benchmark."""
        self.benchmark_path = os.path.abspath(path)

    def set_dirs(self, output_dir: str, jacks_dir: str):
        """Register host-side output and hacks directories.

        Called by the pipeline immediately after ``_ensure_dirs()``.  These
        directories are mounted into the persistent container as ``/output``
        and ``/hacks`` so that state written by one phase is visible to the
        next without round-tripping through the host Python process.
        """
        self._output_dir = os.path.abspath(output_dir)
        self._jacks_dir = os.path.abspath(jacks_dir)

    @property
    def workspace(self) -> str:
        """Benchmark root as seen by the running command."""
        return "/workspace" if self.enabled else self.benchmark_path

    @property
    def tools_mount(self) -> str:
        """Tools directory as seen by the running command."""
        return "/tools" if self.enabled else self.tools_dir

    @property
    def results_dir(self) -> str:
        """Directory where tools write structured JSON results."""
        return self._results_dir

    def result_file(self, filename: str) -> str | None:
        """Return host path to *filename* inside the results dir, or None."""
        path = os.path.join(self._results_dir, filename)
        return path if os.path.isfile(path) else None

    # ------------------------------------------------------------------
    # Docker availability
    # ------------------------------------------------------------------

    @staticmethod
    def _docker_ok() -> bool:
        try:
            if not shutil.which("docker"):
                return False
            cp = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return cp.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    async def ensure_image(self, emit=None):
        """Build the sandbox image if it does not already exist."""
        if not self.enabled or self._image_ready:
            return

        proc = await asyncio.create_subprocess_exec(
            "docker", "images", "-q", IMAGE_TAG,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        if out.strip():
            self._image_ready = True
            return

        if emit:
            await emit("log", {
                "phase": "setup",
                "text": "Building sandbox Docker image (first run only) …",
            })

        proc = await asyncio.create_subprocess_exec(
            "docker", "build",
            "-t", IMAGE_TAG,
            "-f", str(DOCKERFILE),
            str(DOCKERFILE.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if emit:
                await emit("log", {"phase": "setup", "text": f"[docker-build] {text}"})
        await proc.wait()

        if proc.returncode != 0:
            log.warning("Docker image build failed — falling back to host execution")
            self.enabled = False
            return

        self._image_ready = True

    # ------------------------------------------------------------------
    # Persistent container — post-setup phases
    # ------------------------------------------------------------------

    async def start_main_container(self, emit=None) -> None:
        """Start a persistent Docker container for all post-setup phases.

        Mounts:
          /workspace  ← benchmark repo  (benchmark_path)
          /output     ← pipeline output dir (_output_dir)
          /hacks      ← jacks dir          (_jacks_dir)
          /tools      ← static-analysis tools (read-only)
          /results    ← temp dir for tool JSON output
          /home/user  ← writable copy of ~/.claude with fresh credentials

        Subsequent ``stream_ai()`` calls use ``docker exec`` into this
        container instead of spawning fresh ``docker run`` instances, so
        authentication and filesystem state persist across phases.

        If the container fails to start the sandbox falls back silently to
        per-invocation ephemeral containers.
        """
        if not self.enabled or self._container_id:
            return

        await self.ensure_image(emit)
        self._prepare_claude_dir()

        args = [
            "docker", "run",
            "--rm",
            "--detach",
            "--security-opt", "no-new-privileges",
            "--cap-drop=ALL",
            "--memory=4g",
            "--cpus=2",
            "--pids-limit=512",
            "-v", f"{self.tools_dir}:/tools:ro",
            "-v", f"{self._results_dir}:/results",
            "-e", "BENCHJACK_RESULTS_DIR=/results",
        ]

        if self.benchmark_path:
            args += ["-v", f"{self.benchmark_path}:/workspace"]
        if self._output_dir:
            args += ["-v", f"{self._output_dir}:/output"]
        if self._jacks_dir:
            args += ["-v", f"{self._jacks_dir}:/hacks"]

        # Prefer explicit ANTHROPIC_API_KEY from the environment (stable);
        # only fall back to the short-lived OAuth access token from Keychain.
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            args += ["-e", f"ANTHROPIC_API_KEY={api_key}"]
        else:
            creds_json = _extract_claude_credentials()
            oauth_token = (creds_json or {}).get("claudeAiOauth", {}).get("accessToken")
            if oauth_token:
                args += ["-e", f"ANTHROPIC_API_KEY={oauth_token}"]

        args += [
            "-v", f"{self._claude_dir}:/home/user",
            "-e", "HOME=/home/user",
            "--user", f"{os.getuid()}:{os.getgid()}",
            IMAGE_TAG,
            "sleep", "infinity",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
        except Exception as exc:
            log.warning("Could not start main container (%s) — using ephemeral mode", exc)
            return

        if proc.returncode == 0:
            self._container_id = out.decode().strip()
            log.info("Started main sandbox container %s", self._container_id[:12])
            if emit:
                await emit("log", {
                    "phase": "setup", "msg_type": "text",
                    "text": f"[sandbox] Main container started ({self._container_id[:12]})",
                })
        else:
            err_text = err.decode().strip()
            log.warning("Failed to start main container (%s) — using ephemeral mode", err_text)
            if emit:
                await emit("log", {
                    "phase": "setup", "msg_type": "text",
                    "text": "[sandbox] Warning: could not start persistent container; using ephemeral mode",
                })

    async def stop_main_container(self) -> None:
        """Stop the persistent container if it is running."""
        if not self._container_id:
            return
        cid = self._container_id
        self._container_id = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "stop", cid,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
        except Exception as exc:
            log.warning("Failed to stop container %s: %s", cid[:12], exc)

    # ------------------------------------------------------------------
    # Static-tool execution (no network)
    # ------------------------------------------------------------------

    async def run_tool(self, cmd: list[str]) -> str:
        """Run *cmd* in a static-profile container (``--network=none``).

        Returns combined stdout+stderr.
        Falls back to host subprocess when Docker is unavailable.
        """
        if not self.enabled:
            env = {**os.environ, "BENCHJACK_RESULTS_DIR": self._results_dir}
            return await self._host_exec(cmd, cwd=self.benchmark_path, env=env)

        docker_cmd = self._base_docker_args(network=False) + cmd
        return await self._docker_exec(docker_cmd)

    # ------------------------------------------------------------------
    # AI-CLI execution (network allowed)
    # ------------------------------------------------------------------

    async def stream_ai(
        self,
        shell_cmd: str,
        *,
        stdin_data: str | None = None,
    ) -> AsyncGenerator[str, None]:
        """Run *shell_cmd* in an AI-profile container (network enabled).

        When a persistent container is running (post-setup phases), uses
        ``docker exec`` so auth and state survive across phases.
        Otherwise starts an ephemeral ``docker run`` (setup phase).

        Yields stdout lines for real-time streaming.
        Falls back to host subprocess when Docker is unavailable.
        """
        if not self.enabled:
            async for line in self._host_stream_shell(shell_cmd, stdin_data=stdin_data):
                yield line
            return

        if self._container_id:
            # Post-setup: exec into the persistent container
            docker_cmd = ["docker", "exec", "-i", self._container_id, "sh", "-c", shell_cmd]
        else:
            # Setup phase: ephemeral container
            docker_cmd = self._base_docker_args(network=True, ai=True) + [
                "sh", "-c", shell_cmd,
            ]

        proc = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=1024 * 1024,  # 1 MB — stream-json lines can exceed 64 KB default
        )

        if stdin_data:
            proc.stdin.write(stdin_data.encode())
            proc.stdin.close()

        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            yield raw.decode(errors="replace").rstrip("\n")

        await proc.wait()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self):
        if self._container_id:
            cid = self._container_id
            self._container_id = None
            try:
                subprocess.run(
                    ["docker", "stop", cid],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except Exception:
                pass
        if self._results_dir and os.path.isdir(self._results_dir):
            shutil.rmtree(self._results_dir, ignore_errors=True)
        if self._claude_dir and os.path.isdir(self._claude_dir):
            shutil.rmtree(self._claude_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internals — HOME / credentials setup
    # ------------------------------------------------------------------

    def _prepare_claude_dir(self) -> None:
        """Set up a writable HOME copy with fresh credentials.  Idempotent."""
        if self._claude_dir:
            return

        self._claude_dir = tempfile.mkdtemp(prefix="benchjack_claude_")

        # Copy ~/.claude/ directory
        dot_claude_dest = os.path.join(self._claude_dir, ".claude")
        claude_dir = Path.home() / ".claude"
        if claude_dir.is_dir():
            shutil.copytree(
                str(claude_dir), dot_claude_dest,
                dirs_exist_ok=True, ignore_dangling_symlinks=True,
                copy_function=shutil.copy2,
            )
        else:
            os.makedirs(dot_claude_dest, exist_ok=True)

        # Copy ~/.claude.json (main config, separate from the dir)
        claude_json_src = Path.home() / ".claude.json"
        claude_json_dest = os.path.join(self._claude_dir, ".claude.json")
        if claude_json_src.is_file():
            shutil.copy2(str(claude_json_src), claude_json_dest)

        # Inject fresh OAuth credentials from macOS Keychain into ~/.claude.json
        # so Claude Code in the Linux container can use the refresh-token flow
        # without needing Keychain access.
        creds_json = _extract_claude_credentials()
        if creds_json:
            config: dict = {}
            if os.path.isfile(claude_json_dest):
                try:
                    with open(claude_json_dest) as fh:
                        config = json.load(fh)
                except Exception:
                    config = {}
            config.update(creds_json)
            with open(claude_json_dest, "w") as fh:
                json.dump(config, fh)

        # Copy ~/.codex/ so Codex can find its OAuth session
        codex_dir = Path.home() / ".codex"
        if codex_dir.is_dir():
            shutil.copytree(
                str(codex_dir), os.path.join(self._claude_dir, ".codex"),
                dirs_exist_ok=True, ignore_dangling_symlinks=True,
                copy_function=shutil.copy2,
            )

    # ------------------------------------------------------------------
    # Internals — Docker argument builder (ephemeral containers)
    # ------------------------------------------------------------------

    def _base_docker_args(self, *, network: bool, ai: bool = False) -> list[str]:
        """Build docker-run argument list for an ephemeral container.

        Used for: static-analysis tools (ai=False) and setup-phase AI calls
        (ai=True, before the persistent container is started).
        """
        args = [
            "docker", "run", "--rm",
            "--security-opt", "no-new-privileges",
            "--cap-drop=ALL",
            "--memory=4g",
            "--cpus=2",
            "--pids-limit=512",
            "-v", f"{self.tools_dir}:/tools:ro",
            "-v", f"{self._results_dir}:/results",
            "-e", "BENCHJACK_RESULTS_DIR=/results",
        ]
        if self.benchmark_path:
            args += ["-v", f"{self.benchmark_path}:/workspace"]
        if not network:
            args += ["--network", "none"]
        if ai:
            # Prefer explicit ANTHROPIC_API_KEY from the environment (stable);
            # only fall back to the short-lived OAuth access token from Keychain.
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                args += ["-e", f"ANTHROPIC_API_KEY={api_key}"]
            else:
                creds_json = _extract_claude_credentials()
                oauth_token = (creds_json or {}).get("claudeAiOauth", {}).get("accessToken")
                if oauth_token:
                    args += ["-e", f"ANTHROPIC_API_KEY={oauth_token}"]
            self._prepare_claude_dir()
            args += [
                "-v", f"{self._claude_dir}:/home/user",
                "-e", "HOME=/home/user",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-i",
            ]
        args.append(IMAGE_TAG)
        return args

    async def _docker_exec(self, cmd: list[str]) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        return out.decode(errors="replace")

    # ------------------------------------------------------------------
    # Internals — Host fallback
    # ------------------------------------------------------------------

    async def _host_exec(
        self, cmd: list[str], cwd: str | None = None, env: dict | None = None,
    ) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=env,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        return out.decode(errors="replace")

    async def _host_stream_shell(
        self,
        shell_cmd: str,
        *,
        cwd: str | None = None,
        stdin_data: str | None = None,
    ) -> AsyncGenerator[str, None]:
        proc = await asyncio.create_subprocess_shell(
            shell_cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd or self.benchmark_path,
            limit=1024 * 1024,
        )
        if stdin_data:
            proc.stdin.write(stdin_data.encode())
            proc.stdin.close()
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            yield raw.decode(errors="replace").rstrip("\n")
        await proc.wait()
