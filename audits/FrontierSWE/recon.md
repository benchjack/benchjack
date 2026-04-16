# Reconnaissance Report — FrontierSWE

FrontierSWE is a benchmark of **17 ultra-long-horizon (20-hour) coding tasks** distributed by Proximal Labs. It uses the **Harbor** orchestrator with a custom `ManagedModalEnvironment` (`harbor_ext/modal_managed.py`), and runs each agent inside a per-task **Modal Sandbox** built from a published Docker image (`ghcr.io/proximal-labs/frontier-swe/<task>:v1`).

## 1. Entry points

- `pyproject.toml` declares the `harbor_ext` package; orchestration is driven by Harbor reading `tasks/*/job.yaml` (e.g. `tasks/cranelift-codegen-opt/job.yaml:1-66`). Each `job.yaml` lists the agents (claude-code, codex, gemini-cli, qwen-code, kimi-cli, opencode-cli) and a single task path.
- `oracle.yaml` provides an oracle-mode run (`HARBOR_ORACLE_MODE=1`) that bypasses anti-cheat.
- Per-task **verifier entry** is `tasks/<task>/tests/test.sh`; it invokes `tests/compute_reward.py` to emit `reward.json` / `reward.txt` in `/logs/verifier/`.

## 2. Evaluation / scoring code

- One `compute_reward.py` per task; many tasks gate hard on correctness (e.g. `tasks/cranelift-codegen-opt/tests/compute_reward.py:344-360` zeros score on anti-cheat / build / correctness failure).
- Scoring formulas vary: weighted-harmonic-mean speedup (cranelift), pass-rate (lua-native), tinker-LoRA solve count (frogsgame), reference-binary diff (dependent-type-checker).

## 3. Task configuration

- Each task has `task.toml` (resources, docker_image, allow_internet), `job.yaml` (agents+orchestrator), `instruction.md` (agent prompt), `environment/Dockerfile`, `solution/solve.sh` (sometimes), `tests/test.sh`+`compute_reward.py`.
- Hidden answers/test data live in `tests/` and are unpacked at runtime: `tests-bundle.tar.gz`, `golden.tar.gz`, `hidden_test_set_bundle.zip`, `hidden-scenes.tar.gz`, `git-test-suite.tar.gz`, etc. — agent never sees `/tests/`.
- `cranelift-codegen-opt` even encrypts the pristine baseline (`/opt/.harbor-baseline.enc` decrypted with `tests/baseline.key`, `tests/test.sh:43-72`).

## 4. Execution environment

- Modal sandbox per trial; **no Docker-in-Docker** — agent shares the container with `/app/` (writable workspace) and the verifier mounts `/tests/` and `/logs/verifier/` separately.
- `task.toml` sets `cpus`, `memory_mb`, `storage_mb`, `gpus`, `allow_internet` (false for 15/17 tasks; true for `frogsgame-rl` and `pcqm4mv2-autoresearch`).
- Network is allowlisted by `harbor_ext/network_allowlist.py`; agent CLIs only reach their model APIs.
- Agents and verifier run **in the same container** at different phases — significant trust boundary risk (the verifier's `test.sh` performs heavy hardening: PATH reset, `unset PYTHONPATH/LD_PRELOAD`, `rm /etc/ld.so.preload`, integrity checksum of `/usr/lib/.vfy-sha256`, etc., e.g. `tasks/dart-style-haskell/tests/test.sh:9-30`).

## 5. LLM-as-judge

- **No LLM is used as a judge.** All tasks score via deterministic execution of test inputs and numeric metrics (perf, correctness, diff). frogsgame-rl uses an LLM (Qwen3-8B) as the *agent under test*, not as the judge.

## 6. Trust boundaries

- Agent writes freely to `/app/`. Verifier reads agent artifacts (binaries, source files) and **executes them** (cargo build, run wasmtime on benchmarks, run formatter via strace, etc.).
- Several tasks restore pristine test infrastructure from encrypted archives (cranelift) or scan for tampering (dart-style does PATH/LD_PRELOAD/binary-integrity sweeps).
- `dependent-type-checker/tests/test.sh:25-32` greps agent source for forbidden strings (`compute_reward`, `/logs/verifier`, etc.) — string-pattern, easy to obfuscate.
- Many `compute_reward.py` files trust JSON / state files written during `test.sh` (e.g. lua's `--verifier-state`); a malicious agent that influenced those files could shift scoring.

## 7. Cost estimate

**Heavy.** Per-task agent timeout is 20 hours (72,000 s), verifier timeout 24 hours, sandbox up to 50 GB storage and 128 GB RAM, gated behind `ghcr.io/proximal-labs` images (require `GHCR_TOKEN`) and Modal infra. Running the full suite as designed requires Modal compute + GHCR access. Static-only inspection of the verifier code (this audit) is lightweight.

## Task ID manifest

Wrote `benchjack_task_ids.json` (17 entries) at `output/frontier-swe/repo/`, mapping each task slug to its `task.toml`.
