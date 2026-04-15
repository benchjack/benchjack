"""
AI CLI runner — wraps `claude` (Claude Code) or `codex` (OpenAI Codex) as
async subprocess generators.

Uses ``--output-format stream-json --verbose`` for Claude Code so that each
tool call and assistant turn arrives as a separate SSE-friendly event rather
than as a single blob after generation completes.

When a :class:`~server.sandbox.Sandbox` is provided, AI invocations run
inside a Docker container.  Otherwise they run directly on the host.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sandbox import Sandbox


class RateLimitError(RuntimeError):
    """Raised when the AI backend reports a usage limit has been reached."""


@dataclass
class RunResult:
    output: str
    exit_code: int


class AIRunner:
    """Async wrapper for Claude Code / Codex CLI invocations."""

    def __init__(
        self,
        backend: str = "auto",
        model: str | None = None,
        sandbox: Sandbox | None = None,
    ):
        self.backend = self._detect(backend)
        self.model = model
        self.sandbox = sandbox

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect(preference: str) -> str:
        if preference != "auto":
            if shutil.which(preference):
                return preference
            raise RuntimeError(f"Requested backend '{preference}' not found in PATH")
        for name in ("claude", "codex"):
            if shutil.which(name):
                return name
        raise RuntimeError(
            "Neither 'claude' nor 'codex' found in PATH. "
            "Install Claude Code (npm i -g @anthropic-ai/claude-code) "
            "or OpenAI Codex."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def stream(self, prompt: str, *, cwd: str | None = None):
        """Yield human-readable lines as they arrive from the AI backend.

        For Claude Code this uses ``stream-json`` output format internally
        and converts each event into readable text, so callers always get
        plain strings.
        """
        if self.sandbox and self.sandbox.enabled:
            async for line in self._stream_sandboxed(prompt):
                yield line
            return

        if self.backend == "claude":
            async for line in self._stream_claude(prompt, cwd):
                yield line
        elif self.backend == "codex":
            async for line in self._stream_codex(prompt, cwd):
                yield line
        else:
            raise RuntimeError(f"Unknown backend: {self.backend}")

    async def run(self, prompt: str, *, cwd: str | None = None) -> RunResult:
        """Run to completion and return the full output."""
        lines: list[str] = []
        exit_code = 0
        try:
            async for event in self.stream(prompt, cwd=cwd):
                if event.get("msg_type") == "text":
                    lines.append(event["text"])
        except Exception:
            exit_code = 1
        return RunResult(output="\n".join(lines), exit_code=exit_code)

    # ------------------------------------------------------------------
    # Sandboxed execution
    # ------------------------------------------------------------------

    async def _stream_sandboxed(self, prompt: str):
        """Run the AI CLI inside the Docker sandbox.

        Uses stream-json for Claude so events arrive incrementally.
        """
        if self.backend == "claude":
            shell_cmd = (
                "claude --print --dangerously-skip-permissions"
                " --output-format stream-json --verbose"
            )
            if self.model:
                shell_cmd += f" --model {self.model}"
        elif self.backend == "codex":
            shell_cmd = "codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check"
        else:
            raise RuntimeError(f"Unknown backend: {self.backend}")

        if self.backend == "claude":
            # Parse stream-json events from the sandbox stream
            async for raw_line in self.sandbox.stream_ai(
                shell_cmd, stdin_data=prompt,
            ):
                # Each line is a JSON event from stream-json
                for parsed in self._parse_stream_json_line(raw_line):
                    yield parsed
        else:
            async for line in self.sandbox.stream_ai(
                shell_cmd, stdin_data=prompt,
            ):
                yield {"msg_type": "text", "text": line}

    # ------------------------------------------------------------------
    # Direct host — Claude Code  (stream-json --verbose)
    # ------------------------------------------------------------------

    async def _stream_claude(self, prompt: str, cwd: str | None):
        fd, prompt_path = tempfile.mkstemp(suffix=".md", prefix="bjprompt_")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(prompt)

            shell_cmd = (
                "claude --print --dangerously-skip-permissions"
                " --output-format stream-json --verbose"
            )
            if self.model:
                shell_cmd += f" --model {self.model}"
            shell_cmd += f' < "{prompt_path}"'

            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                limit=1024 * 1024,  # 1 MB — stream-json lines can exceed 64 KB default
            )

            async for line in self._read_and_parse_stream_json(proc):
                yield line

            await proc.wait()
        finally:
            try:
                os.unlink(prompt_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Direct host — Codex
    # ------------------------------------------------------------------

    async def _stream_codex(self, prompt: str, cwd: str | None):
        fd, prompt_path = tempfile.mkstemp(suffix=".md", prefix="bjprompt_")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(prompt)

            shell_cmd = f'codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check < "{prompt_path}"'
            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                limit=1024 * 1024,
            )
            async for line in self._read_lines(proc):
                yield {"msg_type": "text", "text": line}
            await proc.wait()
        finally:
            try:
                os.unlink(prompt_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # stream-json parser
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_and_parse_stream_json(proc):
        """Read stream-json lines from a subprocess and yield parsed output.

        Event types emitted by ``claude --print --output-format stream-json --verbose``:

        * ``system``    -- session init (ignored)
        * ``assistant`` -- a model turn; content blocks are ``text`` or ``tool_use``
        * ``user``      -- tool results returned to the model (large; summarised)
        * ``result``    -- final outcome (duplicates assistant text; skipped)
        """
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            for parsed in AIRunner._parse_stream_json_line(line):
                yield parsed

    @staticmethod
    def _parse_stream_json_line(line: str):
        """Parse a single stream-json line and yield structured event dicts.

        Yields dicts with ``msg_type`` key:
          - ``{"msg_type": "text", "text": "..."}``
          - ``{"msg_type": "tool_call", "name": "...", "summary": "..."}``
          - ``{"msg_type": "tool_result", "chars": N}``
        """
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            if "You've hit your limit" in line:
                raise RateLimitError(line)
            yield {"msg_type": "text", "text": line}
            return

        etype = evt.get("type")

        if etype == "assistant":
            for block in evt.get("message", {}).get("content", []):
                btype = block.get("type")
                if btype == "text":
                    text = block.get("text", "")
                    if "You've hit your limit" in text:
                        raise RateLimitError(text)
                    yield {"msg_type": "text", "text": text}
                elif btype == "tool_use":
                    name = block.get("name", "?")
                    inp = block.get("input", {})
                    yield {
                        "msg_type": "tool_call",
                        "name": name,
                        "summary": _summarise_tool_input(name, inp),
                    }

        elif etype == "user":
            content = evt.get("message", {}).get("content", [])
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    cdata = block.get("content", "")
                    if isinstance(cdata, str):
                        chars = len(cdata)
                    elif isinstance(cdata, list):
                        chars = sum(len(str(c)) for c in cdata)
                    else:
                        chars = len(str(cdata))
                    yield {"msg_type": "tool_result", "chars": chars}

        elif etype == "result":
            # The result event duplicates assistant text already streamed
            # above — only check for rate-limit errors, don't re-yield.
            result_text = evt.get("result", "")
            if isinstance(result_text, str) and "You've hit your limit" in result_text:
                raise RateLimitError(result_text)

        # system, rate_limit_event -- silently skipped

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_lines(proc):
        """Yield decoded lines from a subprocess stdout (fallback reader)."""
        buffer = ""
        while True:
            try:
                raw = await asyncio.wait_for(proc.stdout.read(512), timeout=0.15)
            except asyncio.TimeoutError:
                if buffer:
                    yield buffer
                    buffer = ""
                continue
            if not raw:
                break
            buffer += raw.decode(errors="replace")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                yield line
        if buffer:
            yield buffer


def _summarise_tool_input(name: str, inp: dict) -> str:
    """Return a short string summarising a tool call's input."""
    if name == "Read":
        return inp.get("file_path", "?")
    if name == "Grep":
        return f'/{inp.get("pattern", "?")}/ in {inp.get("path", ".")}'
    if name == "Glob":
        return inp.get("pattern", "?")
    if name == "Bash":
        cmd = inp.get("command", "?")
        return cmd if len(cmd) < 120 else cmd[:117] + "..."
    if name == "Edit":
        return inp.get("file_path", "?")
    if name == "Write":
        return inp.get("file_path", "?")
    if name in ("WebFetch", "WebSearch"):
        return inp.get("url", inp.get("query", "?"))
    # Generic fallback
    s = json.dumps(inp, ensure_ascii=False)
    return s if len(s) < 120 else s[:117] + "..."
