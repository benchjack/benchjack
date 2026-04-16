# FrontierSWE

- **Upstream repo:** <https://github.com/Proximal-Labs/frontier-swe>
- **Upstream commit:** [`d2ba265`](https://github.com/Proximal-Labs/frontier-swe/commit/d2ba265a79b1b5a7ba34763802cb43720a183f67) (2026-04-16)
- **Audited on:** 2026-04-16
- **Backend:** `claude`
- **Mode:** `audit`
- **Auditor:** BenchJack maintainers

## Summary

FrontierSWE is 17 ultra-long-horizon (20-hour) coding tasks orchestrated by Harbor on Modal sandboxes. Every task runs the agent phase and the verifier phase **inside the same container** — so V1 (no isolation) and V3 (verifier builds/runs agent-authored code) are architectural and propagate to V7 (scorer trusts agent-produced output) across the majority of tasks. Anti-cheat is grep-based, making V5 systemic. V4 (LLM judge) is **absent** — all scoring is deterministic. The most exploitable tasks are `libexpat-to-x86asm` (plain-text AES keys on shared FS), `modular-stack-wan21` (`.oracle_solution` touch bypass), `frogsgame-rl` (internet + `TINKER_API_KEY`), `optimizer-design` (agent-supplied `CustomOptimizer` can forge loss), and `revideo-perf-opt` (`cp` baseline mp4 → SSIM≈1).

## Findings

| Class | Name | Prevalence | Severity |
|-------|------|------------|----------|
| V1 | No Isolation Between Agent and Evaluator | all 17 tasks | high |
| V2 | Answers Shipped With the Test | many tasks | high |
| V3 | RCE on Untrusted Input | majority of tasks | high |
| V4 | LLM Judge Without Sanitization | — | n/a |
| V5 | Weak String Matching (anti-cheat) | most tasks | medium |
| V6 | Evaluation Logic Gaps | multiple tasks | medium |
| V7 | Trusting Output of Untrusted Code | majority of tasks | high |
| V8 | Unnecessary Permissions | root agent, GPU exposure, 2× internet-on tasks | medium |

Per-task/per-class detail in [`task_results.json`](task_results.json) (69 entries across all 17 tasks).

## Reproduction

```bash
benchjack https://github.com/Proximal-Labs/frontier-swe --no-ui
```

Static-only inspection; no Modal compute or GHCR images required. Full benchmark execution would require Modal infra plus a `GHCR_TOKEN` for the `ghcr.io/proximal-labs/frontier-swe/<task>:v1` images.

## Artifacts

- [`recon.md`](recon.md) — reconnaissance report (entry points, scoring, trust boundaries)
- [`vuln_scan.md`](vuln_scan.md) — V1–V8 walkthrough with file:line citations
- [`task_results.json`](task_results.json) — structured per-task, per-class findings
- [`task_ids.json`](task_ids.json) — task slug → `task.toml` manifest (17 entries)

## Disclosure

- [x] Not applicable — findings describe architectural patterns documented in the public repo; no new live-service exploit.
