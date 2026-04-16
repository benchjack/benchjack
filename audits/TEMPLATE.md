# <BenchmarkName>

- **Upstream repo:** <https://github.com/org/benchmark>
- **Upstream commit:** [`<short-sha>`](https://github.com/org/benchmark/commit/<full-sha>) (YYYY-MM-DD commit date) — or tag `vX.Y.Z`
- **Audited on:** YYYY-MM-DD
- **Backend:** `claude` | `codex` — model `<model-id>`
- **Mode:** `audit` | `hack-it`
- **Auditor:** @your-github-handle

## Summary

One paragraph: is this benchmark hackable? What's the headline exploit? What score could an agent achieve by abusing it, versus solving it legitimately?

## Findings

| Class | Name | Severity | Notes |
|-------|------|----------|-------|
| V1 | No Isolation | — | |
| V2 | Answers Shipped With the Test | — | |
| V3 | RCE on Untrusted Input | — | |
| V4 | LLM Judge Without Sanitization | — | |
| V5 | Weak String Matching | — | |
| V6 | Evaluation Logic Gaps | — | |
| V7 | Trusting Untrusted Code Output | — | |
| V8 | Unnecessary Permissions | — | |

Fill in severity (`critical` / `high` / `medium` / `low` / `n/a`) and a short note for each class that applies. Drop rows that don't apply.

## Headline exploit

Describe the most effective attack in 2–5 sentences. Link to PoC code under `poc/` if provided.

**Estimated score by exploitation:** `~NN%` on `<N>` tasks.

## Reproduction

```bash
# Exact command used
benchjack <target> --no-ui --poc-level partial
```

Notes on environment (OS, Python version, whether Docker sandbox was used, any non-default flags).

## Artifacts

- [`findings.json`](findings.json) — structured BenchJack report (optional)
- [`poc/`](poc/) — runnable proof-of-concept (optional)
- [`notes.md`](notes.md) — extended reproduction notes (optional)

## Disclosure

- [ ] Maintainers notified on YYYY-MM-DD
- [ ] Disclosure window elapsed / fix released / coordinated with maintainers
- [ ] Not applicable (e.g., benchmark archived, exploit is generic)
