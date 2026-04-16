# Vulnerability Scan — FrontierSWE (17 tasks)

## V1: No Isolation Between Agent and Evaluator — **PRESENT (all 17 tasks)**

Every task shares a single Modal sandbox between the agent phase and the verifier phase (`harbor_ext/modal_managed.py:699-770` — one `Sandbox.create` per trial; no user separation, no PID namespace, no distinct FS). Agent runs write `/app`; verifier reads `/app` and writes `/logs/verifier` in the same container, same user, same process tree. Only a subset of tasks apply perimeter hardening (PATH reset, `LD_PRELOAD`/`ld.so.preload` cleanup, integrity checksums): `dart-style-haskell/tests/test.sh:12-30`, `pyright-type-checking-optimization/tests/test.sh:18-20`, `granite-mamba2-inference-optimization/tests/test.sh:20-76`. The remaining 14 tasks have no such hardening — an agent-planted binary on `$PATH`, `LD_PRELOAD`, or `/etc/ld.so.preload` will be honored by the verifier.

## V2: Answers Shipped With the Test — **PRESENT (multiple tasks)**

The shared-container design means `/tests/` is readable to any process with the verifier's privileges. Concretely:
- `libexpat-to-x86asm/tests/{libexpat_key.txt,gcc_key.txt}` contain plain-text AES keys that decrypt the bundled libexpat binaries (`test.sh:28-38`).
- `cranelift-codegen-opt/tests/baseline.key` is the pristine-baseline decryption key; `test.sh:467-470` gives agent-compiled wasm WASI access (`--dir "${bench_dir}::."`) to each benchmark's `*.expected` oracle.
- `git-to-zig/test.sh:19-22` unpacks `git-test-suite.tar.gz` into `/tmp/git-test-suite` (shared FS).
- `dependent-type-checker/test.sh:11-13` unpacks accept/reject corpus + `reference_impl/` into `/tests/` on the shared FS.
- `inference-system-optimization/tests/prompts.jsonl` — the correctness prompts — reside in `/tests/` and are reachable from `/app`.
- `modular-stack-wan21/test.sh:39-46` restores `/verifier-data` from `/opt/verifier-data.tar.gz` — agent can read it before the verifier phase.
- `frogsgame-rl/task.toml` grants internet + `TINKER_API_KEY` + allows prepare.py to import from /app.
- `notebook-compression/test.sh:61-66` extracts `hidden_test_set_bundle.zip` into `/tmp/` on the shared FS.
- `pcqm4mv2-autoresearch`: hidden labels extracted into `/tmp/pcqm4mv2_test_set.XXXXXX` on shared FS.
- `optimizer-design`: hidden workloads under `/tests/hidden_workloads/*.py` readable from /app during verifier phase.

## V3: Remote Code Execution on Untrusted Input — **PRESENT (majority of tasks)**

Frontier-SWE's design is that the **verifier builds and runs agent-authored code** inside the verifier container, with no further sandbox. Severe cases:
- `ffmpeg-swscale-rewrite/tests/compute_reward.py:22-33` imports `pixel_formats`, `load_swscale_library`, `image_to_bytes` from `/app/pixel_formats.py` — unchecked; agent controls all comparison logic.
- `frogsgame-rl/tests/compute_reward.py:693-695` and `:918-921` import `EvalHarness`, `USER_MESSAGE`, `build_system_prompt` from `/app/prepare.py`.
- `optimizer-design/tests/test.sh:55-58` — verifier imports `CustomOptimizer` from `/app/custom_optimizer.py`; the import allowlist is static-AST only — bypassed with `__import__`, `getattr`, cpp_extension.
- `postgres-sqlite-wire-adapter/tests/test.sh:245` — verifier symlinks and executes agent binary as `postgres`/`initdb`/`pg_ctl`.
- `inference-system-optimization/tests/test.sh:294-309` — verifier executes `/app/submission/launch_server.sh` as bash with root env.
- `pyright-type-checking-optimization/tests/test.sh:92-101`, `:174-302` — verifier runs agent-built `dist/pyright.js` under `node` with host FS access.
- `revideo-perf-opt/tests/test.sh:177-191` — verifier runs agent-authored packages via `node benchmark.mjs`.
- `modular-stack-wan21` — verifier imports `candidate_pipeline` from agent code.
- `notebook-compression/scoring_core.py:114` — `subprocess.run([run_path, stage])` on agent-owned executable with full env inheritance.
- `cranelift-codegen-opt/test.sh:197` — cargo-builds agent-modified source that can include modified `build.rs` files (anti-cheat only flags *new* ones at `test.sh:168-170`).

## V4: LLM Judges Without Input Sanitization — **ABSENT**

No task uses an LLM as a scoring judge; all scores are deterministic. `frogsgame-rl` uses Qwen3-8B via Tinker, but as the *agent under test*, not a judge.

## V5: Weak String Matching — **PRESENT (anti-cheat scans)**

Almost every task's anti-cheat is a `grep -lE` source scan on specific extensions — trivially bypassed by base64/concatenation/non-matching file extensions:
- `cranelift-codegen-opt/test.sh:156-158` — `grep -lE 'dlopen|libLLVM'`, only `*.rs|*.isle`.
- `dependent-type-checker/test.sh:25` — literal-path regex.
- `frogsgame-rl/test.sh:45-47` — substring grep of `*.py|*.sh` only; excludes `prepare.py`.
- `inference-system-optimization/test.sh:41-54` — extension-restricted, excludes hidden dirs (`.oracle_solution` planting viable).
- `postgres-sqlite-wire-adapter/test.sh:60-72` — only `.zig|.zon|.txt|.md|.sh|.json`.
- `revideo-perf-opt/test.sh:34` — misses `*.d.ts`, Python, wasm.
- `optimizer-design/test.sh:74-98` — static AST allowlist.
- `granite-mamba2-inference-optimization/test.sh:78-87` — fixed-string regex bypassed by `getattr`.
- `libexpat-to-x86asm/compute_reward.py:72` + runtest log parsing — grep-only PASS scan in agent-controlled output.

## V6: Evaluation Logic Gaps — **PRESENT (multiple tasks)**

- `inference-system-optimization/test.sh:66-70` — agent can plant `/app/.oracle_solution` marker (skipped by anti-cheat) to set `ORACLE_FLAG`.
- `modular-stack-wan21/test.sh:17-34` — stripping of reference Python only happens when `.oracle_solution` is absent; agent `touch` bypasses stripping.
- `granite-mamba2-inference-optimization/compute_reward.py:1205` — timing-sanity "suspicious" flag is recorded but doesn't zero the score.
- `postgres-sqlite-wire-adapter/test.sh:429-447`, `:492-529` — TAP parser fills missing tests with "pass" when `exit_code==0`.
- `postgres-sqlite-wire-adapter/compute_reward.py:46-48` — `tests_total` inflated to 738 only when no hard_fail; crashes leave tiny denominator → `pass_rate = tests_passed/max(tests_total,1)`.
- `lua-native-compiler/test.sh:107-113` — reference-lua-copy detection is "warning only, not a hard fail".
- `notebook-compression/compute_reward.py:469` / scoring_core.py:182 — geometric-mean ratio attackable with empty compressed files + full artifact.
- `revideo-perf-opt/compute_reward.py:336` — duration check falls through on `except Exception`.
- `pyright-type-checking-optimization/compute_reward.py:83-84` — <4-benchmark gate still permits scoring from a very narrow success subset.
- `cranelift-codegen-opt/test.sh:168-170` — only flags *newly added* build.rs; modification of existing build.rs allowed.

## V7: Trusting the Output of Untrusted Code — **PRESENT (majority of tasks)**

Because the verifier runs agent artifacts (V3) and reads log files written by those artifacts, the scorer trusts agent-produced data end-to-end:
- `git-to-zig/compute_reward.py:73-79, :175` — TAP `ok` lines are emitted by the agent's own `git` binary directly into `$result_file`; no expected-test-count cross-check. Spamming `ok` passes the test.
- `libexpat-to-x86asm/compute_reward.py:72-182` — trusts PASS log lines and "X secs" timing strings printed by agent-linked `.so` constructors.
- `ffmpeg-swscale-rewrite` — agent's `load_swscale_library`/`image_to_bytes` route candidate through baseline → PSNR `inf`.
- `modular-stack-wan21` — `generate_video` is agent code; returning reference frames satisfies PSNR ≥ 25 dB.
- `postgres-sqlite-wire-adapter/test.sh:429-447` — TAP fill-to-total trusts agent stdout.
- `lua-native-compiler` — ELF magic check only (`test.sh:290-297`); a wrapper that execs `/verifier-data/lua` passes.
- `dart-style-haskell` — agent binary produces formatter output that strace observes; memoized-replay attack viable.
- `revideo-perf-opt` — agent packages run baseline video generation in same container; candidate can `cp` baseline mp4 to reach SSIM≈1.
- `pcqm4mv2-autoresearch/compute_reward.py:350` — subprocesses `submission/predict.py --count-params` and trusts JSON line of its stdout.
- `dependent-type-checker/compute_reward.py:100-160` — trusts only exit codes from agent binary on corpus files; a binary hashing `(file contents)` against leaked labels passes.

## V8: Granting Unnecessary Permissions — **PRESENT**

- Agents run as root-equivalent in every sandbox (Modal default, no user drop configured).
- `frogsgame-rl` and `pcqm4mv2-autoresearch` set `allow_internet = true`; frogsgame injects `TINKER_API_KEY` as an env secret (task.toml:27).
- GPU-enabled tasks expose H100/B200 directly to agent code: `granite-mamba2-inference-optimization`, `inference-system-optimization`, `modular-stack-wan21`, `optimizer-design`, `pcqm4mv2-autoresearch`.
- Storage ceilings are large (`notebook-compression: 150 GB`, `pcqm4mv2: 150 GB`, `optimizer-design: 100 GB`).
- Network egress, when enabled, is allowlisted CIDRs but still includes full model-API access which can exfiltrate/import holdout data.

## Summary

**V1, V3, V5, V7, V8 are systemic across the benchmark.** The architecture — single shared Modal sandbox, verifier imports/runs agent code, anti-cheat is regex-grep — means even well-hardened tasks (`dart-style-haskell`, `pyright-type-checking-optimization`, `granite-mamba2`) have residual V3/V7 exposure. Three tasks stand out as most hackable: `frogsgame-rl` (internet + API key + agent-imported prepare.py), `libexpat-to-x86asm` (plain-text keys on shared FS), and `modular-stack-wan21` (oracle-flag bypass + agent-imported candidate). **V4 is absent.** V2/V6 are task-specific.

Now writing the per-task JSONL results.
Audit complete. Wrote 69 JSONL findings across all 17 tasks to `/srv/home/tony/benchjack/output/frontier-swe/repo/benchjack_task_results.jsonl`.

**Key systemic findings:**
- **V1 (shared sandbox)** and **V3 (verifier runs agent code)** are architectural — they affect every task because Harbor's ManagedModalEnvironment gives agent + verifier one container, and most scorers import/exec agent artifacts at scoring time.
- **V7 (trusting agent output)** follows directly: TAP parsers (`git-to-zig`, `postgres-sqlite-wire-adapter`), PSNR on agent-produced frames (`modular-stack-wan21`, `ffmpeg-swscale-rewrite`), SSIM on agent-written MP4s (`revideo-perf-opt`), grep-PASS on agent-linked .so logs (`libexpat-to-x86asm`).
- **V4 (LLM judge)** is **ABSENT** — all rewards are deterministic.
- Most critical single findings: `libexpat-to-x86asm` (plain-text AES keys on shared FS), `modular-stack-wan21` (`.oracle_solution` touch bypass), `frogsgame-rl` (internet + TINKER_API_KEY), `optimizer-design` (CustomOptimizer can forge loss → unbounded speedup), `revideo-perf-opt` (cp baseline mp4 → SSIM=1).
