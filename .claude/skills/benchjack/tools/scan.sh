#!/usr/bin/env bash
# BenchJack Scanner — Orchestrator
# Runs all benchjack static analysis tools against a benchmark codebase
# and produces a unified report.
#
# Usage: ./scan.sh <target-directory>
#
# Tools run:
#   1. Semgrep (custom benchjack rules) — V1-V8
#   2. Bandit (Python security linter) — V3 focus
#   3. Docker Config Analyzer — V1, V2, V8
#   4. Trust Boundary Mapper — V1, V3, V7
#   5. Hadolint (Dockerfile linter) — V8
#
# Output: /tmp/benchjack_scan_report.txt + per-tool JSON in /tmp/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?Usage: $0 <target-directory>}"
TARGET="$(cd "$TARGET" && pwd)"
REPORT="/tmp/benchjack_scan_report.txt"

echo "================================================================"
echo " BenchJack Full Scan"
echo " Target: $TARGET"
echo " Time:   $(date)"
echo "================================================================"
echo ""

# Track tool statuses
declare -A TOOL_STATUS
declare -A TOOL_FINDINGS

# --- Helper ---
run_tool() {
    local name="$1"
    local cmd="$2"
    echo ">>> Running: $name"
    echo "---"
    if eval "$cmd" 2>&1; then
        TOOL_STATUS["$name"]="OK"
    else
        TOOL_STATUS["$name"]="FAILED (exit $?)"
    fi
    echo ""
    echo ""
}

# =========================================================
# 1. Semgrep
# =========================================================
echo "########################################"
echo "# 1/5  SEMGREP (custom rules, V1-V8)  #"
echo "########################################"
echo ""

SEMGREP_RULES="$SCRIPT_DIR/benchjack_semgrep_rules.yml"

if command -v semgrep &>/dev/null; then
    echo "[semgrep] Running with benchjack rules..."
    semgrep --config "$SEMGREP_RULES" "$TARGET" \
        --json \
        --timeout 60 \
        -q \
        > /tmp/benchjack_semgrep_results.json 2>/dev/null || true

    # Count findings
    SEMGREP_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('/tmp/benchjack_semgrep_results.json'))
    results = d.get('results', [])
    print(len(results))
except:
    print(0)
" 2>/dev/null || echo 0)

    echo "[semgrep] Found $SEMGREP_COUNT finding(s)"

    # Show human-readable summary
    semgrep --config "$SEMGREP_RULES" "$TARGET" \
        --timeout 60 \
        -q \
        2>/dev/null || true

    TOOL_STATUS["semgrep"]="OK ($SEMGREP_COUNT findings)"
else
    echo "[semgrep] Not installed. Install: pip install semgrep"
    echo "[semgrep] Skipping."
    TOOL_STATUS["semgrep"]="SKIPPED (not installed)"
fi

echo ""
echo ""

# =========================================================
# 2. Bandit
# =========================================================
echo "########################################"
echo "# 2/5  BANDIT (Python security, V3)    #"
echo "########################################"
echo ""

run_tool "bandit" "bash '$SCRIPT_DIR/run_bandit.sh' '$TARGET'"

echo ""

# =========================================================
# 3. Docker Config Analyzer
# =========================================================
echo "########################################"
echo "# 3/5  DOCKER ANALYZER (V1, V2, V8)   #"
echo "########################################"
echo ""

run_tool "docker_analyzer" "python3 '$SCRIPT_DIR/docker_analyzer.py' '$TARGET'"

echo ""

# =========================================================
# 4. Trust Boundary Mapper
# =========================================================
echo "########################################"
echo "# 4/5  TRUST MAPPER (V1, V3, V7)      #"
echo "########################################"
echo ""

run_tool "trust_mapper" "python3 '$SCRIPT_DIR/trust_map.py' '$TARGET'"

echo ""

# =========================================================
# 5. Hadolint
# =========================================================
echo "########################################"
echo "# 5/5  HADOLINT (Dockerfile, V8)       #"
echo "########################################"
echo ""

run_tool "hadolint" "bash '$SCRIPT_DIR/run_hadolint.sh' '$TARGET'"

echo ""

# =========================================================
# Summary
# =========================================================
echo "================================================================"
echo " SCAN COMPLETE"
echo "================================================================"
echo ""
echo "Tool Status:"
for tool in semgrep bandit docker_analyzer trust_mapper hadolint; do
    status="${TOOL_STATUS[$tool]:-NOT RUN}"
    echo "  $tool: $status"
done
echo ""
echo "Output files:"
echo "  /tmp/benchjack_semgrep_results.json  — Semgrep findings"
echo "  /tmp/benchjack_bandit_results.json   — Bandit findings"
echo "  /tmp/benchjack_bandit_readable.txt   — Bandit human-readable"
echo "  /tmp/benchjack_docker_results.json   — Docker analyzer findings"
echo "  /tmp/benchjack_trust_map.json        — Trust boundary map"
echo ""
echo "Use these results to inform the Phase 2 vulnerability assessment."
