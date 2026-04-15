# CLAUDE.md

## Project Overview

BenchJack is an AI agent benchmark hackability scanner with a real-time web dashboard. It runs a multi-phase audit pipeline (static analysis + AI-powered deep inspection via Claude Code or Codex) and streams results to a live web UI.

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, uvicorn
- **Frontend**: Vanilla HTML/CSS/JS (no framework), SSE for real-time streaming
- **AI Backends**: Claude Code CLI, OpenAI Codex CLI
- **Static Analysis**: Semgrep, Bandit, Hadolint
- **Sandboxing**: Docker (containers with `--network=none`, `--cap-drop=ALL`)

## Repository Layout

```
benchjack.py                CLI entry point (argparse, web/CLI mode dispatch)
server/
  app.py                    FastAPI server (SSE streaming, REST API)
  pipeline.py               Audit pipeline orchestrator (phases: setup, static, recon, vulnscan, poc, report)
  ai_runner.py              Claude Code / Codex CLI wrapper
  sandbox.py                Docker sandbox management
web/
  index.html                Dashboard UI
  style.css                 Dark-themed styles
  app.js                    Frontend logic (SSE client)
Dockerfile.sandbox          Sandbox container image
.claude/skills/benchjack/
  SKILL.md                  Original skill definition
  tools/                    Static analysis tool scripts (semgrep rules, bandit, hadolint, docker_analyzer, trust_map)
```

## Common Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run with web UI (default)
python benchjack.py <target>

# Run in CLI-only mode (defaults: claude, audit, no sandbox)
python benchjack.py <target> --no-ui

# Run without Docker sandbox
python benchjack.py <target> --no-sandbox

# Install as editable package
pip install -e .
```

## Development Notes

- The web server runs on port 7832 by default
- Two modes: web UI mode (default, opens browser) and CLI mode (`--no-ui`)
- In `--no-ui` mode the defaults are backend=`claude`, mode=`audit`, and sandbox disabled; callers can override with `--backend codex`, `--hack-it`, or `--sandbox`
- Static analysis tools live in `.claude/skills/benchjack/tools/` and are invoked by the pipeline
- The sandbox Docker image (`benchjack-sandbox`) is built automatically on first run
- Dependencies are minimal: only `fastapi` and `uvicorn` (see `requirements.txt` and `pyproject.toml`)
- The pipeline emits events via an `emit()` callback pattern, consumed by either the SSE server or CLI printer
- Vulnerability classes are V1-V8, defined in the pipeline and SKILL.md
