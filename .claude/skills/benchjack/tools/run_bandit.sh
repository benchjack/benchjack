#!/usr/bin/env bash
# BenchJack Bandit Wrapper
# Runs Bandit with focus on benchmark-relevant security issues.
# Covers V3 (code execution) primarily, with some V7 overlap.
#
# Usage: ./run_bandit.sh <target-directory>

set -euo pipefail

TARGET="${1:?Usage: $0 <target-directory>}"

if ! command -v bandit &>/dev/null; then
    echo "[bandit] bandit not found. Installing..."
    pip3 install bandit --quiet 2>/dev/null || pip install bandit --quiet
fi

if [ ! -d "$TARGET" ]; then
    echo "[bandit] Error: '$TARGET' is not a directory."
    exit 1
fi

echo "================================================================"
echo " BenchJack Bandit Scan"
echo " Target: $TARGET"
echo "================================================================"
echo ""

# Bandit test IDs relevant to benchmark hackability:
#   B102 - exec_used
#   B103 - set_bad_file_permissions
#   B104 - hardcoded_bind_all_interfaces
#   B108 - hardcoded_tmp_directory
#   B301 - pickle
#   B302 - marshal
#   B303 - md5/sha1 (weak hash for integrity)
#   B306 - mktemp_q
#   B307 - eval
#   B310 - urllib_urlopen
#   B312 - telnetlib
#   B321 - ftp
#   B323 - unverified_context (SSL)
#   B501 - request_with_no_cert_validation
#   B506 - yaml_load
#   B602 - subprocess_popen_with_shell_equals_true
#   B603 - subprocess_without_shell_equals_true
#   B604 - any_other_function_with_shell_equals_true
#   B605 - start_process_with_a_shell
#   B606 - start_process_with_no_shell
#   B607 - start_process_with_partial_path
#   B608 - hardcoded_sql_expressions
#   B609 - wildcard_injection

RELEVANT_TESTS="B102,B103,B108,B301,B302,B307,B310,B506,B602,B603,B604,B605,B606,B607"
RESULTS_DIR="${BENCHJACK_RESULTS_DIR:-/tmp}"

echo "[bandit] Running focused scan (tests: $RELEVANT_TESTS)..."
echo ""

# Run bandit, allow non-zero exit (findings produce exit code 1)
bandit \
    -r "$TARGET" \
    -t "$RELEVANT_TESTS" \
    -f json \
    --severity-level medium \
    -q \
    2>/dev/null > "$RESULTS_DIR/benchjack_bandit_raw.json" || true

# Also produce human-readable output
bandit \
    -r "$TARGET" \
    -t "$RELEVANT_TESTS" \
    --severity-level medium \
    -q \
    2>/dev/null > "$RESULTS_DIR/benchjack_bandit_readable.txt" || true

# Map bandit findings to benchjack vulnerability classes
python3 - "$RESULTS_DIR" <<'PYEOF'
import json
import os
import sys

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BENCHJACK_RESULTS_DIR", "/tmp")

VULN_MAP = {
    "B102": ("V3", "exec() usage"),
    "B301": ("V3", "pickle deserialization"),
    "B302": ("V3", "marshal deserialization"),
    "B307": ("V3", "eval() usage"),
    "B506": ("V3", "yaml.load() without SafeLoader"),
    "B602": ("V3", "subprocess with shell=True"),
    "B603": ("V3", "subprocess call"),
    "B604": ("V3", "function call with shell=True"),
    "B605": ("V3", "process started with shell"),
    "B606": ("V3", "process started without shell"),
    "B607": ("V3", "process started with partial path"),
    "B108": ("V1", "hardcoded /tmp directory (shared filesystem)"),
    "B103": ("V8", "permissive file permissions"),
    "B310": ("V2", "urllib urlopen (potential answer fetch)"),
}

try:
    with open(os.path.join(RESULTS_DIR, "benchjack_bandit_raw.json")) as f:
        data = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    print("[bandit] No findings or failed to parse output.")
    sys.exit(0)

results = data.get("results", [])
if not results:
    print("[bandit] No relevant findings.")
    sys.exit(0)

# Group by vulnerability class
by_vuln = {}
for r in results:
    test_id = r.get("test_id", "")
    vuln_class, desc = VULN_MAP.get(test_id, ("?", r.get("test_name", "")))
    key = vuln_class
    if key not in by_vuln:
        by_vuln[key] = []
    by_vuln[key].append({
        "file": r.get("filename", ""),
        "line": r.get("line_number", 0),
        "severity": r.get("issue_severity", ""),
        "confidence": r.get("issue_confidence", ""),
        "test_id": test_id,
        "description": desc,
        "detail": r.get("issue_text", ""),
        "code": r.get("code", "").strip(),
    })

print(f"[bandit] Found {len(results)} findings across {len(by_vuln)} vulnerability classes.\n")

for vuln_class in sorted(by_vuln.keys()):
    findings = by_vuln[vuln_class]
    print(f"--- {vuln_class}: {len(findings)} finding(s) ---")
    for f in findings:
        print(f"  {f['file']}:{f['line']} [{f['severity']}/{f['confidence']}]")
        print(f"    {f['test_id']}: {f['description']}")
        print(f"    {f['detail']}")
        if f['code']:
            for line in f['code'].split('\n')[:3]:
                print(f"    > {line}")
        print()

# Write structured output
with open(os.path.join(RESULTS_DIR, "benchjack_bandit_results.json"), "w") as f:
    json.dump({"findings_by_vulnerability": by_vuln, "total": len(results)}, f, indent=2)

print(f"[bandit] Structured results written to {os.path.join(RESULTS_DIR, 'benchjack_bandit_results.json')}")
PYEOF

echo ""
echo "[bandit] Human-readable report at $RESULTS_DIR/benchjack_bandit_readable.txt"
echo "[bandit] Done."
