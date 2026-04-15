# Contributing to BenchJack

Thanks for your interest in contributing! This guide covers how to set up a development environment, run the project locally, and submit changes.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) for package management
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (`npm i -g @anthropic-ai/claude-code`) or [OpenAI Codex](https://github.com/openai/codex) — needed for AI-powered pipeline phases
- Docker (optional) — for sandboxed execution
- Without Docker: install `semgrep`, `bandit`, and `hadolint` locally for static analysis

## Development Setup

```bash
# Clone the repo
git clone https://github.com/benchjack/benchjack.git
cd benchjack

# Install in editable mode
uv pip install -e ".[tools]"
```

This gives you the `benchjack` CLI and installs the static analysis tools (semgrep, bandit).

## Running Locally

```bash
# Web UI mode — opens a browser at http://localhost:7832
benchjack

# Web UI with a target pre-loaded
benchjack ./path/to/benchmark

# CLI-only mode
benchjack ./path/to/benchmark --no-ui

# CLI with Docker sandbox
benchjack ./path/to/benchmark --no-ui --sandbox
```

The web server runs on port 7832 by default (`--port` to change). In web UI mode, the dashboard streams results in real time via SSE.

## Project Structure

```
benchjack.py              CLI entry point (argparse, web/CLI dispatch)
server/
  app.py                  FastAPI application factory
  ai_runner.py            Claude Code / Codex CLI wrapper
  sandbox.py              Docker sandbox management
  event_bus.py            SSE pub-sub for real-time streaming
  pipeline/
    audit.py              5-phase audit pipeline
    hack.py               Reward-hack pipeline
    prompts.py            AI prompt templates
    models.py             Data models
    utils.py              Pipeline helpers
  routes/
    audit.py              Audit control endpoints
    events.py             SSE streaming endpoint
    runs.py               Run management endpoints
    static.py             Static file serving
web/
  index.html              Dashboard UI
  style.css               Styles
  app.js                  Legacy frontend entry (being split into modules)
  js/                     Frontend JS modules (state, ui, handlers, etc.)
.claude/skills/benchjack/
  tools/                  Static analysis tool scripts (semgrep rules, bandit, hadolint, etc.)
Dockerfile.sandbox        Container image for sandboxed execution
```

## Making Changes

1. **Create a branch** off `main`:
   ```bash
   git checkout -b my-feature
   ```

2. **Make your changes.** A few guidelines:
   - Backend code is in `server/`. The pipeline emits events via an `emit()` callback, consumed by the SSE server (web mode) or a CLI printer.
   - Frontend is vanilla HTML/CSS/JS in `web/` — no build step required. Just edit and reload.
   - Static analysis tools live in `.claude/skills/benchjack/tools/`. These are shell/Python scripts invoked by the pipeline inside or outside Docker.
   - Vulnerability classes are V1–V8 (defined in `server/pipeline/prompts.py` and `.claude/skills/benchjack/SKILL.md`).

3. **Test your changes locally.** Run BenchJack against a small benchmark repo and verify:
   - The web UI renders correctly and streams events.
   - CLI mode produces expected output.
   - If you changed static analysis tools, verify they run in both host and sandboxed modes.

4. **Commit and push:**
   ```bash
   git add <files>
   git commit -m "Short description of the change"
   git push origin my-feature
   ```

5. **Open a pull request** against `main`. Describe what you changed and why.

## Where to Contribute

There are many ways to help — from quick wins to deeper projects. Here are some ideas:

### Benchmark adapters

BenchJack currently starts every audit from scratch, running full reconnaissance on the target. For well-known benchmarks (SWE-bench, WebArena, GAIA, etc.), much of this structure is already understood. Adding **adapter interfaces** that encode known evaluation architecture — entry points, scoring logic, isolation boundaries — would let the pipeline skip reconnaissance and jump straight to vulnerability scanning, making audits faster and more accurate.

### PoC verification oracles

Right now, proof-of-concept exploits are generated but not automatically verified. If you're familiar with a benchmark's execution harness, you can contribute **verification oracles** that actually run the PoC against the benchmark's tooling and confirm whether the exploit succeeds. This closes the loop between "we think this is exploitable" and "here's proof."

### Prompt engineering

The AI-powered phases (recon, vuln scan, PoC, report) are driven by prompt templates in `server/pipeline/prompts.py`. There's a lot of room to improve these — better structured output, fewer false positives, more consistent severity ratings, or better adaptation to different benchmark styles. If you have experience with prompt optimization, this is high-leverage work.

### Performance and efficiency

The pipeline currently runs phases sequentially and makes conservative choices about how much context to feed the AI. Contributions that improve throughput — parallelizing independent analysis steps, smarter context windowing, caching repeated work across runs, or reducing unnecessary AI round-trips — are very welcome.

### New vulnerability classes

The current taxonomy covers V1–V8. If you've seen benchmark exploits that don't fit neatly into these categories, propose new classes. This involves updating `server/pipeline/prompts.py`, `.claude/skills/benchjack/SKILL.md`, and the frontend vulnerability metadata in `web/app.js`.

### Static analysis tools and rules

The static analysis phase runs Semgrep, Bandit, Hadolint, a Docker analyzer, and a trust mapper. You can contribute:
- New Semgrep rules targeting benchmark-specific anti-patterns (rules live in `.claude/skills/benchjack/tools/benchjack_semgrep_rules.yml`)
- Integrations with other static tools (e.g., CodeQL, Trivy, custom linters)
- New analysis scripts in `.claude/skills/benchjack/tools/`

### UI and UX

The web dashboard is vanilla HTML/CSS/JS with no build step. Try running BenchJack against a few benchmarks and note what's confusing, broken, or missing. Contributions to usability, accessibility, mobile responsiveness, better visualizations of findings, or smoother run management are all welcome.

### Documentation

Improving the README, adding architecture diagrams, writing tutorials for common workflows, or documenting how to add a new vulnerability class or static tool.

More importantly, please run the tool on your benchmarks before you evaluate!

## Reporting Bugs

Open a GitHub issue with:
- What you ran (command, target benchmark).
- What you expected vs. what happened.
- Any error output or logs.

## Code Style

- Python: follow PEP 8. Keep imports organized (stdlib, third-party, local).
- JavaScript: vanilla JS, no framework dependencies. Use `const`/`let`, no `var`.
- Keep dependencies minimal — the project intentionally only requires `fastapi` and `uvicorn` as Python packages.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
