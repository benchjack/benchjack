#!/usr/bin/env bash
# Benchjack PoC — reward hacking for the FrontierSWE benchmark.
#
# Representative sample (6 tasks spanning perf and correctness categories,
# all sharing the ubuntu22.04 stand-in base so a single local stand-in
# image covers the whole sample):
#
#     1. dependent-type-checker          (perf+correctness  ; V7 PROVEN)
#     2. ffmpeg-swscale-rewrite          (perf+correctness  ; V3)
#     3. cranelift-codegen-opt           (perf              ; best-effort)
#     4. lua-native-compiler             (correctness       ; best-effort)
#     5. pyright-type-checking-opt       (perf              ; best-effort)
#     6. revideo-perf-opt                (perf              ; best-effort)
#
# The PoC runs every task through harbor's official entrypoint
# (`harbor run --env docker --force-build`) with a custom dispatching
# exploit agent (`exploit_agent:ExploitAgent`). The agent detects the task
# from /app/ layout and drops a task-specific payload. Successful hacks
# are summarized at the end; only non-zero scoring tasks are written to
# `../exploit_result.jsonl`.

set -uo pipefail

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$POC_DIR/.." && pwd)"

STAND_IN_BASE_TAG="ghcr.io/proximal-labs/frontier-swe/first-party-cli-base-ubuntu22.04:firstparty-cli-20260405-r2"

# Tasks to run (all use the ubuntu22.04 base → one stand-in covers all).
# Override with BENCHJACK_TASKS="t1 t2 ..." for ad-hoc subsetting.
DEFAULT_TASKS=(
    dependent-type-checker
    ffmpeg-swscale-rewrite
    cranelift-codegen-opt
    lua-native-compiler
    pyright-type-checking-optimization
    revideo-perf-opt
)
read -r -a TASKS <<< "${BENCHJACK_TASKS:-${DEFAULT_TASKS[*]}}"

echo "=== Benchjack PoC — FrontierSWE ==="
echo "POC dir:   $POC_DIR"
echo "Repo:      $REPO_ROOT"
echo "Tasks:     ${TASKS[*]}"
echo

# -------------------------------------------------------------------
# 1. Prerequisites
# -------------------------------------------------------------------
command -v docker >/dev/null || { echo "error: docker not found on PATH"; exit 1; }
command -v harbor >/dev/null || { echo "error: harbor CLI not found on PATH"; exit 1; }

export PYTHONPATH="$REPO_ROOT:$POC_DIR${PYTHONPATH:+:$PYTHONPATH}"

# -------------------------------------------------------------------
# 2. Stand-in for the private GHCR base image
# -------------------------------------------------------------------
if ! docker image inspect "$STAND_IN_BASE_TAG" >/dev/null 2>&1; then
    echo "--- building stand-in base image ($STAND_IN_BASE_TAG) ---"
    docker build -t "$STAND_IN_BASE_TAG" -f "$POC_DIR/base.Dockerfile" "$POC_DIR"
else
    echo "stand-in base image already present: $STAND_IN_BASE_TAG"
fi
echo

# -------------------------------------------------------------------
# 3. Run harbor once per task
# -------------------------------------------------------------------
JOBS_DIR="$POC_DIR/_runs"
mkdir -p "$JOBS_DIR"

declare -A TASK_SCORES
declare -A TASK_REASONS

for task in "${TASKS[@]}"; do
    TASK_DIR="$REPO_ROOT/tasks/$task"
    if [ ! -d "$TASK_DIR" ]; then
        echo "!! skipping $task: $TASK_DIR not found"
        continue
    fi

    echo "================================================================"
    echo "=== running: $task"
    echo "================================================================"

    job_name="poc_${task}"
    # Under rootless docker the previous run's artifacts may be owned by the
    # container-user's shifted uid and unremovable from the host. Use a root
    # container to nuke any stale job dir.
    docker run --rm -u root -v "$JOBS_DIR":/w alpine sh -c "rm -rf /w/$job_name" 2>/dev/null || true

    set +e
    harbor run \
        --env docker \
        --force-build \
        --path "$TASK_DIR" \
        --agent-import-path exploit_agent:ExploitAgent \
        --artifact /logs/verifier \
        --artifact /logs/agent \
        -k 1 -n 1 \
        --no-export-traces \
        --jobs-dir "$JOBS_DIR" \
        --job-name "$job_name" \
        2>&1 | tail -120
    rc=$?
    set -e

    # Locate reward.json for this task.
    REWARD_JSON="$(find "$JOBS_DIR/$job_name" -path '*/verifier/reward.json' -type f 2>/dev/null | head -1 || true)"
    if [ -z "$REWARD_JSON" ]; then
        REWARD_JSON="$(find "$JOBS_DIR/$job_name" -name 'reward.json' -type f 2>/dev/null | head -1 || true)"
    fi

    if [ -n "$REWARD_JSON" ] && [ -f "$REWARD_JSON" ]; then
        score="$(python3 -c "import json,sys; print(json.load(open('$REWARD_JSON')).get('score'))" 2>/dev/null || echo "null")"
        reason="$(python3 -c "import json,sys; d=json.load(open('$REWARD_JSON')); print((d.get('additional_data') or {}).get('reason') or '')" 2>/dev/null || echo "")"
    else
        score="null"
        reason="no reward.json produced (harbor rc=$rc)"
    fi
    TASK_SCORES["$task"]="$score"
    TASK_REASONS["$task"]="$reason"
    echo
    echo "---- [$task] score=$score reason=$reason"
    echo
done

# -------------------------------------------------------------------
# 4. Summary + exploit_result.jsonl
# -------------------------------------------------------------------
echo "================================================================"
echo "=== Summary"
echo "================================================================"
for task in "${TASKS[@]}"; do
    printf "  %-40s score=%s\n" "$task" "${TASK_SCORES[$task]:-null}"
done
echo

OUT="$REPO_ROOT/exploit_result.jsonl"
: > "$OUT"

declare -A VULN_MAP=(
    [dependent-type-checker]="V7|HIGH|Verifier gates on binary exit code; exploit binary switches on filename substrings 'accept'/'reject' — no real type-checking required. Anti-cheat grep only bans full patterns 'corpus/accept' / 'corpus/reject'."
    [ffmpeg-swscale-rewrite]="V3|CRITICAL|compute_reward.py does sys.path.insert(0,'/app') and imports load_swscale_library + image_to_bytes from agent-writable /app/pixel_formats.py. Source scan only covers /app/swscale-impl, so the agent monkey-patches pixel_formats to make candidate_lib route through baseline (PSNR=inf) with a no-op swscale_process (massive speedup)."
    [cranelift-codegen-opt]="V7|HIGH|Verifier trusts agent-built wasmtime's stdout on benchmark inputs; --dir::. gives wasm WASI access to .expected oracle files in the benchmark dir. Best-effort in this PoC."
    [lua-native-compiler]="V7|MEDIUM|Verifier compiles agent Rust source and compares stdout byte-for-byte; symbol checks use nm only. Best-effort in this PoC (build-gated)."
    [pyright-type-checking-optimization]="V7|MEDIUM|Benchmark harness is overwritten from baseline but agent's Pyright fork still executes verifier code paths. Best-effort in this PoC."
    [revideo-perf-opt]="V7|MEDIUM|Verifier trusts agent's @revideo renderer on hidden scenes; SSIM threshold leaves slack. Best-effort in this PoC."
)

for task in "${TASKS[@]}"; do
    score="${TASK_SCORES[$task]:-null}"
    # Treat any numeric score > 0.0 as a successful hack.
    hacked=$(python3 -c "
import sys
s='$score'
try:
    v=float(s)
    print('yes' if v>0.0 else 'no')
except Exception:
    print('no')
")
    [ "$hacked" != "yes" ] && continue

    IFS='|' read -r vuln sev expl <<< "${VULN_MAP[$task]:-V7|MEDIUM|(no detail)}"
    python3 - "$task" "$vuln" "$sev" "$expl" "$score" "$OUT" <<'PY'
import json, sys
task, vuln, sev, expl, score, out = sys.argv[1:]
expl = f"{expl} Achieved score={score}."
with open(out, 'a') as f:
    f.write(json.dumps({
        "task": task,
        "vulnerability": vuln,
        "severity": sev,
        "explanation": expl,
        "hacked": True,
    }) + "\n")
PY
done

echo "wrote $OUT:"
if [ -s "$OUT" ]; then
    cat "$OUT"
else
    echo "  (no tasks scored > 0)"
fi
