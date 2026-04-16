# Audits

This folder is a community-maintained archive of BenchJack audit results on AI agent benchmarks.

Each subfolder documents a single benchmark audit — what was found, how severe it is, and (where possible) a working proof-of-concept exploit. The goal is to have a shared, verifiable record of benchmark hackability that researchers, benchmark authors, and leaderboard maintainers can reference and reproduce.

If you use BenchJack on a benchmark, please consider contributing your results here.

## Layout

```
audits/
  README.md                  # this file
  TEMPLATE.md                # copy this when adding a new audit
  <BenchmarkName>/
    README.md                # human-readable summary of findings
    findings.json            # (optional) BenchJack structured report
    poc/                     # (optional) proof-of-concept exploit code
    notes.md                 # (optional) reproduction steps, caveats, environment
```

Use a short, recognizable name for the benchmark folder (e.g. `SWE-Bench_Verified`, `Terminal-Bench`, `WebArena`). Match the name used by the benchmark's authors where possible.

## What to include

At minimum, each audit should contain a `README.md` with:

- **Benchmark** — name and upstream repo URL
- **Upstream commit** — full SHA of the benchmark repo at audit time (link to `github.com/<org>/<repo>/commit/<sha>`); add a tag too if the benchmark publishes releases. This pins the audit to a specific version so readers can tell when findings are still applicable.
- **Audited on** — date (YYYY-MM-DD)
- **BenchJack commit** — full SHA of this repo when the audit was run (link to `github.com/benchjack/benchjack/commit/<sha>`)
- **Backend** — `claude` or `codex`, plus the model used
- **Summary** — one paragraph describing the overall hackability of the benchmark
- **Findings** — a table of vulnerability classes (V1–V8) triggered, with severity
- **Exploit** — one-sentence description of the most effective attack, plus estimated score an agent could achieve by abusing it
- **Reproduction** — the exact command you ran (e.g. `benchjack https://github.com/org/bench --no-ui`)

Optionally include the raw BenchJack output (`findings.json`, logs) and runnable PoC code under `poc/`.

See [`TEMPLATE.md`](TEMPLATE.md) for a copy-pasteable skeleton, and [`FrontierSWE/`](FrontierSWE/) for a worked example.

## How to contribute an audit

1. **Run BenchJack** on the target benchmark. CLI mode is easiest for producing shareable artifacts:
   ```bash
   benchjack <target> --no-ui --poc-level partial
   ```
2. **Create a new folder** under `audits/` using the benchmark's name.
3. **Copy `TEMPLATE.md`** into `audits/<BenchmarkName>/README.md` and fill it in.
4. **(Optional) Attach artifacts** — structured findings, logs, or PoC code. Keep large raw logs out of git; prefer a trimmed-down `findings.json` under ~1 MB.
5. **Open a pull request** titled `audits: add <BenchmarkName>`. Include a one-paragraph PR description summarizing the most severe finding.

## What to leave out

- **Secrets** — API keys, session tokens, or credentials captured during the run. Scrub before committing.
- **Upstream benchmark source** — don't vendor the benchmark repo into your audit folder. Link to the upstream commit instead.
- **Large binaries / datasets** — reference by URL.
- **Exploits against live services** — PoCs should target the benchmark's own evaluation harness, not third-party infrastructure.

## Responsible disclosure

Before publishing an audit that reveals a new, high-impact exploit against an actively used benchmark, please notify the benchmark's maintainers and give them a reasonable window to respond (30 days is a common default). Include a note in your audit `README.md` confirming that disclosure has happened.

If you're unsure whether a finding is sensitive, open a draft PR and tag the maintainers — we're happy to help coordinate disclosure.

## Reviewing audits

When reviewing an audit PR, check that:

- The finding is reproducible from the command listed.
- The severity / score claim is backed by the PoC or a clear explanation.
- No secrets or vendored upstream code slipped in.
- The vulnerability class labels (V1–V8) match the actual finding.

## License

Audit writeups in this folder are contributed under the project's Apache 2.0 license (see [`../LICENSE`](../LICENSE)). By opening a PR, you confirm you have the right to publish the content and agree to that license.
