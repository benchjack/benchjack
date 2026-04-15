#!/usr/bin/env python3
"""
BenchJack — AI Agent Benchmark Hackability Scanner

Usage:
    python benchjack.py [TARGET] [OPTIONS]

    TARGET:  Local path, GitHub URL, or owner/repo slug.
             If omitted, the web UI starts and waits for input.

Options:
    --port PORT        Port for the web server (default: 7832)
    --backend NAME     AI backend: claude | codex | auto (default: claude)
    --model MODEL      Model to use for AI analysis
    --poc-level LEVEL  PoC generation level: full | partial | skip (default: partial)
    --no-browser       Don't open a browser automatically
    --no-ui            Run in pure CLI mode (no web server)
    --audit            Run the audit pipeline in CLI mode
    --hack-it          Run the reward-hack pipeline in CLI mode
    --sandbox          Require Docker sandboxing in CLI mode
    --no-sandbox       Run directly on the host

Examples:
    python benchjack.py ./benchmarks/swe-bench
    python benchjack.py https://github.com/org/benchmark
    python benchjack.py princeton-nlp/SWE-bench --backend claude
    python benchjack.py ./my-bench --no-ui
    python benchjack.py ./my-bench --no-ui --hack-it --backend codex --sandbox
"""

import argparse
import asyncio
import shutil
import sys
import webbrowser
from pathlib import Path

TOOLS_DIR = (
    Path(__file__).resolve().parent
    / ".claude" / "skills" / "benchjack" / "tools"
)


# ---- CLI (--no-ui) mode ----

async def cli_run(target, backend, model, mode, use_sandbox, poc_level="partial"):
    """Run the requested pipeline in CLI mode — no web server."""
    from server.ai_runner import AIRunner
    from server.pipeline import AuditPipeline, HackPipeline
    from server.sandbox import Sandbox

    sandbox = Sandbox(str(TOOLS_DIR), enabled=use_sandbox)
    ai = AIRunner(backend=backend, model=model, sandbox=sandbox)

    # Track whether a tool-use spinner is currently shown on the status line
    _tool_active = {"active": False, "calls": 0}

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _clear_status():
        """Erase the spinner status line if one is showing."""
        if _tool_active["active"]:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            _tool_active["active"] = False
            _tool_active["calls"] = 0

    def _show_status(name: str):
        """Show/update the spinner status line for a tool call."""
        _tool_active["calls"] += 1
        n = _tool_active["calls"]
        frame = SPINNER_FRAMES[n % len(SPINNER_FRAMES)]
        label = f"  {frame} Working… (calling {name})" if n == 1 else \
                f"  {frame} Working… ({n} tool calls)"
        sys.stdout.write(f"\r\033[K{label}")
        sys.stdout.flush()
        _tool_active["active"] = True

    async def emit(event_type, data):
        if event_type == "phase_start":
            _clear_status()
            label = data.get("label", data["phase"])
            print(f"\n{'=' * 60}")
            print(f"  {label}")
            print(f"{'=' * 60}\n")

        elif event_type == "log":
            mt = data.get("msg_type", "text")
            if mt == "text":
                _clear_status()
                print(data.get("text", ""))
            elif mt == "tool_call":
                _show_status(data.get("name", "tool"))
            elif mt == "tool_result":
                pass  # keep the spinner, wait for next text

        elif event_type == "finding":
            _clear_status()
            sev = data.get("severity", "?")
            vuln = data.get("vulnerability", "?")
            title = data.get("title", "")
            print(f"\n  >> {vuln} ({sev}): {title}")

        elif event_type == "phase_complete":
            _clear_status()
            dur = data.get("duration", "?")
            fc = data.get("findings_count", 0)
            print(f"\n  -- {data['phase']} complete ({dur}s, {fc} finding(s)) --")

        elif event_type == "audit_complete":
            _clear_status()
            print(f"\n{'=' * 60}")
            if mode == "hack":
                print(f"  Hack run complete")
                print(f"  Results: {data.get('jacks_dir', '')}")
            else:
                total = data.get("total_findings", 0)
                print(f"  Audit complete: {total} finding(s)")
            print(f"{'=' * 60}")

        elif event_type == "error":
            _clear_status()
            print(f"\n  ERROR: {data.get('message', '')}", file=sys.stderr)

    if mode == "hack":
        pipeline = HackPipeline(
            target=target,
            emit=emit,
            ai=ai,
            sandbox=sandbox,
        )
    else:
        pipeline = AuditPipeline(
            target=target,
            emit=emit,
            ai=ai,
            sandbox=sandbox,
            poc_level=poc_level,
        )

    try:
        await pipeline.run()
    finally:
        sandbox.cleanup()


def preflight_checks(backend: str, use_sandbox: bool) -> list[str]:
    """Verify that required external tools are available.

    Returns a list of human-readable error strings (empty == all good).
    """
    errors: list[str] = []

    # -- AI backend ----------------------------------------------------------
    if backend == "auto":
        if not shutil.which("claude") and not shutil.which("codex"):
            errors.append(
                "No AI backend found: neither 'claude' nor 'codex' is on PATH.\n"
                "  Fix: install Claude Code  →  npm i -g @anthropic-ai/claude-code\n"
                "       or install Codex CLI  →  npm i -g @openai/codex"
            )
    elif backend == "claude":
        if not shutil.which("claude"):
            errors.append(
                "'claude' CLI not found on PATH.\n"
                "  Fix: npm i -g @anthropic-ai/claude-code"
            )
    elif backend == "codex":
        if not shutil.which("codex"):
            errors.append(
                "'codex' CLI not found on PATH.\n"
                "  Fix: npm i -g @openai/codex"
            )

    # -- Docker (when sandboxing is requested) --------------------------------
    if use_sandbox:
        if not shutil.which("docker"):
            errors.append(
                "'docker' not found on PATH.\n"
                "  Fix: install Docker Desktop  →  https://docs.docker.com/get-docker/"
            )
        else:
            # docker exists, but the daemon might not be running
            try:
                import subprocess
                result = subprocess.run(
                    ["docker", "info"],
                    capture_output=True, timeout=10,
                )
                if result.returncode != 0:
                    errors.append(
                        "Docker daemon is not running.\n"
                        "  Fix: start Docker Desktop or run 'sudo systemctl start docker'"
                    )
            except (subprocess.TimeoutExpired, OSError):
                errors.append(
                    "Could not reach the Docker daemon (timed out).\n"
                    "  Fix: start Docker Desktop or run 'sudo systemctl start docker'"
                )

    # -- Static analysis tools (when NOT sandboxed) ---------------------------
    # Inside the sandbox container these are pre-installed; on the host the
    # user needs them available.
    if not use_sandbox:
        missing_tools = []
        for tool, install in [
            ("semgrep", "pip install semgrep   or   brew install semgrep"),
            ("bandit",  "pip install bandit"),
        ]:
            if not shutil.which(tool):
                missing_tools.append(f"  - '{tool}' not found.  Fix: {install}")
        if missing_tools:
            errors.append(
                "Static analysis tools missing (required when running without sandbox):\n"
                + "\n".join(missing_tools)
            )

    return errors


def main():
    parser = argparse.ArgumentParser(
        prog="benchjack",
        description="BenchJack — AI Agent Benchmark Hackability Scanner",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="Benchmark path, URL, or owner/repo slug",
    )
    parser.add_argument(
        "--port", type=int, default=7832, help="Web server port (default: 7832)"
    )
    parser.add_argument(
        "--backend",
        default="claude",
        choices=["auto", "claude", "codex"],
        help="AI backend (default: claude)",
    )
    parser.add_argument(
        "--model", default=None, help="Model for AI analysis"
    )
    parser.add_argument(
        "--poc-level",
        default="partial",
        choices=["full", "partial", "skip"],
        help="PoC generation level: full (entire benchmark), partial (sample, default), skip (no PoC)",
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Don't auto-open browser"
    )
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="Run inside the Docker sandbox",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Run tools directly on host instead of in Docker",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Run in CLI mode — print everything to the terminal, no web server",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--audit",
        action="store_true",
        help="Run the audit pipeline in CLI mode",
    )
    mode_group.add_argument(
        "--hack-it",
        action="store_true",
        help="Run the reward-hack pipeline in CLI mode",
    )
    args = parser.parse_args()

    # ---- Guard: pipeline flags are CLI-only ----
    if not args.no_ui:
        ui_only_flags = {
            "--backend": args.backend != parser.get_default("backend"),
            "--model": args.model is not None,
            "--poc-level": args.poc_level != parser.get_default("poc_level"),
            "--audit": args.audit,
            "--hack-it": args.hack_it,
            "--sandbox": args.sandbox,
            "--no-sandbox": args.no_sandbox,
        }
        bad = [flag for flag, set_ in ui_only_flags.items() if set_]
        if bad:
            parser.error(
                f"{', '.join(bad)} cannot be used in web UI mode — "
                "please configure the run from the UI instead. "
                "Add --no-ui to use the CLI."
            )

    # ---- CLI mode ----
    if args.no_ui:
        if not args.target:
            parser.error("--no-ui requires TARGET")

        target = args.target
        mode = "hack" if args.hack_it else "audit"
        use_sandbox = args.sandbox
        sandbox_label = "on" if use_sandbox else "off"
        print(f"BenchJack (CLI mode)")
        print(f"  Target:  {target}")
        print(f"  Mode:    {mode}")
        print(f"  Backend: {args.backend}")
        print(f"  Sandbox: {sandbox_label}")

        # Pre-flight checks
        errors = preflight_checks(backend=args.backend, use_sandbox=use_sandbox)
        if errors:
            print("\nPre-flight checks failed:\n", file=sys.stderr)
            for err in errors:
                print(f"  ✗ {err}\n", file=sys.stderr)
            sys.exit(1)

        asyncio.run(cli_run(
            target=target,
            backend=args.backend,
            model=args.model,
            mode=mode,
            use_sandbox=use_sandbox,
            poc_level=args.poc_level,
        ))
        return

    # ---- Web UI mode ----

    # Pre-flight checks (web mode always uses default backend + sandbox on)
    use_sandbox = not args.no_sandbox
    errors = preflight_checks(backend=args.backend, use_sandbox=use_sandbox)
    if errors:
        print("\nPre-flight checks failed:\n", file=sys.stderr)
        for err in errors:
            print(f"  ✗ {err}\n", file=sys.stderr)
        sys.exit(1)

    # Build the URL
    url = f"http://localhost:{args.port}"
    if args.target:
        url += f"?target={args.target}&autostart=1"

    # Import here so CLI --help is fast
    import uvicorn
    from server.app import create_app

    app = create_app(
        ai_backend=args.backend,
        ai_model=args.model,
        sandbox=not args.no_sandbox,
    )

    # Open browser after short delay
    if not args.no_browser:
        import threading

        def open_browser():
            import time
            time.sleep(1.2)
            webbrowser.open(url)

        threading.Thread(target=open_browser, daemon=True).start()

    sandbox_label = "off" if args.no_sandbox else "Docker (auto)"
    print(f"BenchJack starting at {url}")
    if args.target:
        print(f"  Target:  {args.target}")
    print(f"  Backend: {args.backend}")
    print(f"  Sandbox: {sandbox_label}")
    print()

    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
