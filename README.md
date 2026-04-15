# BenchJack

AI agent benchmark hackability scanner with a real-time web dashboard.

BenchJack runs a multi-phase audit pipeline — static analysis tools plus AI-powered deep inspection (via Claude Code or Codex) — and streams results to a live web interface as they arrive.

## Quick Start

```bash
pip install -r requirements.txt
python benchjack.py <benchmark-path-or-url>
```

A browser opens at `http://localhost:7832` showing the real-time dashboard.

## Usage

```
python benchjack.py [TARGET] [OPTIONS]

TARGET:  Local path, GitHub URL, or owner/repo slug.
         If omitted, the web UI starts and waits for input.

Web UI options:
  --port PORT        Web server port (default: 7832)
  --no-browser       Don't auto-open browser

CLI-only options (require --no-ui):
  --no-ui            Run in pure CLI mode (no web server)
  --audit            Run the audit pipeline
  --hack-it          Run the reward-hack pipeline
  --backend NAME     AI backend: claude | codex | auto (default: claude)
  --model MODEL      Model for AI analysis phases
  --poc-level LEVEL  PoC generation level: full | partial | skip (default: partial)
  --sandbox          Run inside the Docker sandbox
  --no-sandbox       Run tools on host instead of in Docker
```

### Examples

```bash
# Local benchmark (web UI)
python benchjack.py ./benchmarks/swe-bench

# GitHub URL (web UI)
python benchjack.py https://github.com/princeton-nlp/SWE-bench

# GitHub slug (web UI)
python benchjack.py princeton-nlp/SWE-bench

# Pure CLI audit mode with defaults
python benchjack.py ./my-benchmark --no-ui

# CLI with specific model and partial PoC
python benchjack.py ./my-benchmark --no-ui --model claude-sonnet-4-6 --poc-level partial

# CLI reward-hack mode with Codex backend in sandbox
python benchjack.py ./my-benchmark --no-ui --hack-it --backend codex --sandbox

# Skip PoC phase entirely
python benchjack.py ./my-benchmark --no-ui --poc-level skip
```

In `--no-ui` mode, `TARGET` is required. Defaults are:

- backend: `claude`
- mode: `audit`
- poc-level: `partial`
- sandbox: disabled (`--no-sandbox`)

## Pipeline Phases

| Phase | Description | Engine |
|-------|-------------|--------|
| **Setup** | Locate/clone the benchmark | git |
| **Static Scan** | Run Semgrep, Bandit, Docker Analyzer, Trust Mapper, Hadolint | Python/bash tools |
| **Reconnaissance** | Map evaluation architecture, entry points, trust boundaries | AI (Claude/Codex) |
| **Vulnerability Scan** | Check for V1-V8 vulnerability classes | AI (Claude/Codex) |
| **PoC Construction** | Design proof-of-concept exploits (controlled by `--poc-level`) | AI (Claude/Codex) |
| **Report** | Generate a structured audit report | AI (Claude/Codex) |

## Vulnerability Classes

- **V1** — No Isolation Between Agent and Evaluator
- **V2** — Answers Shipped With the Test
- **V3** — Remote Code Execution on Untrusted Input
- **V4** — LLM Judges Without Input Sanitization
- **V5** — Weak String Matching
- **V6** — Evaluation Logic Gaps
- **V7** — Trusting the Output of Untrusted Code
- **V8** — Granting Unnecessary Permissions to the Agent

## Sandbox

Static analysis tools and AI CLI invocations can run inside Docker containers for isolation:

- **Static tools** run with `--network=none`, `--cap-drop=ALL`, and the benchmark mounted read-only.
- **AI analysis** (Claude Code / Codex) runs with network access (needed for API calls) but the benchmark is still read-only and host capabilities are dropped.

The sandbox image (`benchjack-sandbox`) is built automatically on the first run. Subsequent runs reuse the cached image.

Use `--no-sandbox` (CLI mode) to run everything directly on the host. The tool also falls back to host execution automatically if Docker is not detected.

## Prerequisites

- Python 3.11+
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (`npm i -g @anthropic-ai/claude-code`) — recommended; Codex is supported but has a high refusal rate on security-related prompts
- Docker (for sandboxed execution; optional with `--no-sandbox`)
- Without sandbox: `semgrep`, `bandit`, `hadolint` should be installed for static analysis

