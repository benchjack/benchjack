# Manual

## Modes

BenchJack has two modes of operation: **audit** and **hack-it**.

### Audit (default)

```bash
benchjack <target> --no-ui --audit
```

The audit pipeline runs 5 phases:

1. **Setup** — clone or locate the benchmark repo.
2. **Reconnaissance** — map the evaluation architecture, entry points, and trust boundaries.
3. **Vulnerability Scan** — check all 8 vulnerability classes (V1–V8) and produce structured findings.
4. **PoC Construction** — generate proof-of-concept exploit code and run it against the benchmark (controlled by `--poc-level`).
5. **Report** — produce a final audit report summarizing findings and severity.

Use audit mode when you want a systematic analysis of a benchmark's hackability, from surface-level static checks through deep AI-powered reasoning, optionally with a working exploit to prove the vulnerabilities are real.

### Hack-it

```bash
benchjack <target> --no-ui --hack-it
```

Hack-it mode is a fast, 2-phase pipeline that skips the audit and goes straight to exploitation:

1. **Hack** — the AI agent directly attempts to reward-hack the benchmark, writing exploit code from scratch.
2. **Verify & Improve** — the agent reviews its own exploit, fixes issues, and re-runs to maximize the hacked score.

Hack-it mode is useful when you already know a benchmark is vulnerable (e.g., from a prior audit) and want to quickly produce or refine an end-to-end exploit. It reads task IDs and prior findings from the corresponding audit run if one exists.

### When to use which

| | Audit | Hack-it |
|---|---|---|
| Goal | Understand *what* is vulnerable and *why* | Produce a working exploit as fast as possible |
| Phases | 5 (setup → recon → vuln scan → PoC → report) | 2 (hack → verify) |
| Output | Structured findings, severity ratings, audit report | Exploit scripts and hacked scores |
| First run on a new benchmark | Yes | Not recommended — run audit first |
| Iterating on an exploit | Overkill | Yes |

## PoC Levels

The `--poc-level` flag (or the dropdown in the web UI) controls whether and how extensively the PoC Construction phase runs during an audit.

### The three levels

#### `skip` — Vulnerability report only

Skips PoC generation entirely. The pipeline runs through Reconnaissance and Vulnerability Scan, then produces a report listing detected vulnerabilities without attempting to exploit them.

Use this when you just want a quick triage of what classes of issues exist.

#### `partial` — Representative sample (default, recommended)

Generates exploit code and runs it against a **representative sample** of benchmark tasks — typically 1-2 tasks from each category, totaling 5-10 tasks. The PoC is then validated to confirm the exploit actually works on those tasks.

This is the recommended level for most runs:
- **Fast** — minutes instead of hours, since only a sample is exercised.
- **Saves disk space** — benchmark environments can be large; running a sample avoids pulling / building everything.
- **Still demonstrates exploitability** — a working exploit on a representative sample is strong evidence the vulnerability is real.

#### `full` — Entire benchmark

Generates exploit code and runs it against **every task** in the benchmark. The PoC must hack all tasks to get the highest possible score.

Use this when:
- You already have all the sandbox environments set up and ready to go.
- You have the time and compute budget for a complete run.
- You need comprehensive coverage numbers (e.g., "exploited 47/50 tasks") for a paper or report.

### Choosing a level

| Concern | `skip` | `partial` | `full` |
|---------|--------|-----------|--------|
| Runtime | Minutes | Minutes to tens of minutes | Hours (benchmark-dependent) |
| Disk usage | Low | Low–moderate | High (full benchmark environments) |
| Proves exploitability | No | Yes (sample) | Yes (complete) |
| Needs sandbox environments | No | Partially | Yes, all of them |
| Good for initial triage | Yes | Yes | Overkill |
| Good for a final report | Too shallow | Usually sufficient | Best coverage |

### Setting the level

**Web UI:** Select the PoC level from the dropdown before starting the audit.

**CLI:**

```bash
benchjack <target> --no-ui --poc-level skip      # report only
benchjack <target> --no-ui --poc-level partial    # sample (default)
benchjack <target> --no-ui --poc-level full       # full benchmark
```

**Claude Code skill:** The skill always runs in `partial` mode. To change this, use the CLI or web UI instead.

## Output

BenchJack writes results to two directories at the project root: `output/` and `hacks/`.

### `output/` — Raw logs and cloned repos

Each run creates `output/<benchmark-name>/` (audit mode) or `output/hack_<benchmark-name>/` (hack-it mode) containing:

```
output/<benchmark-name>/
  repo/                     Cloned benchmark repository
  setup.log                 Raw log from the setup phase
  recon.log                 Raw log from reconnaissance
  vuln_scan.log             Raw log from vulnerability scan
  poc.log                   Raw log from PoC construction
  report.log                Raw log from report generation
```

These are verbose, machine-readable logs of everything the AI agent did in each phase. Useful for debugging or understanding the agent's reasoning.

### `hacks/` — Structured results

The `hacks/` directory contains the curated output you'll actually want to look at:

```
hacks/<benchmark-name>/
  state.json                Run metadata (target, backend, phase statuses, durations)
  findings.json             Structured vulnerability findings with severity and class
  task_ids.json             Mapping of benchmark task IDs to file paths
  task_results.json         Per-task results (hacked/not hacked)
  exploit_result.jsonl      Per-task exploit outcomes
  summary/
    recon.md                Human-readable reconnaissance summary
    vuln_scan.md            Human-readable vulnerability scan summary
    poc.md                  Human-readable PoC construction summary
    report.md               Final audit report
  poc/
    run.sh                  Exploit entry point script
    *.py                    Exploit helper scripts
```

For hack-it mode, results go to `hacks/hack_<benchmark-name>/` with the same structure (minus the audit-specific files like `findings.json`).

**Where to start reading:**
- `hacks/<name>/summary/report.md` — the final audit report.
- `hacks/<name>/findings.json` — machine-readable findings for downstream tooling.
- `hacks/<name>/poc/run.sh` — the generated exploit, ready to run.
