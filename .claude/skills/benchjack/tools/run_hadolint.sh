#!/usr/bin/env bash
# BenchJack Hadolint Wrapper
# Runs Hadolint on all Dockerfiles and filters for benchjack-relevant findings.
# Covers V8 (unnecessary permissions) and V1 (isolation issues).
#
# Usage: ./run_hadolint.sh <target-directory>

set -euo pipefail

TARGET="${1:?Usage: $0 <target-directory>}"

if [ ! -d "$TARGET" ]; then
    echo "[hadolint] Error: '$TARGET' is not a directory."
    exit 1
fi

# Check for hadolint
HADOLINT=""
if command -v hadolint &>/dev/null; then
    HADOLINT="hadolint"
elif command -v docker &>/dev/null; then
    HADOLINT="docker run --rm -i hadolint/hadolint"
    echo "[hadolint] Using Docker-based hadolint"
else
    echo "[hadolint] hadolint not found. Install via:"
    echo "  brew install hadolint          # macOS"
    echo "  apt-get install hadolint       # Debian/Ubuntu"
    echo "  docker pull hadolint/hadolint  # Docker"
    echo ""
    echo "Or download from: https://github.com/hadolint/hadolint/releases"
    exit 1
fi

echo "================================================================"
echo " BenchJack Hadolint Scan"
echo " Target: $TARGET"
echo "================================================================"
echo ""

# Find all Dockerfiles
DOCKERFILES=()
while IFS= read -r -d '' file; do
    DOCKERFILES+=("$file")
done < <(find "$TARGET" -type f \( -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" \) -print0 2>/dev/null)

if [ ${#DOCKERFILES[@]} -eq 0 ]; then
    echo "[hadolint] No Dockerfiles found in $TARGET"
    exit 0
fi

echo "[hadolint] Found ${#DOCKERFILES[@]} Dockerfile(s)"
echo ""

# Hadolint rules relevant to benchmark hackability:
#
# DL3002 - Last USER should not be root (V8)
# DL3004 - Do not use sudo (V8)
# DL3007 - Using latest tag (reproducibility)
# DL3008 - Pin versions in apt-get install (reproducibility)
# DL3009 - Delete apt-get lists (image size)
# DL3025 - Use arguments JSON notation (security)
# DL3029 - Do not use --platform with FROM (portability)
# DL4006 - Set SHELL option -o pipefail (reliability)
#
# SC-prefixed rules come from ShellCheck integration:
# SC2086 - Double quote to prevent globbing and word splitting

ALL_RESULTS=""
TOTAL_FINDINGS=0
BENCHJACK_FINDINGS=0

for dockerfile in "${DOCKERFILES[@]}"; do
    echo "--- Scanning: $dockerfile ---"

    # Run hadolint in JSON format
    if [ "$HADOLINT" = "hadolint" ]; then
        RESULT=$($HADOLINT --format json "$dockerfile" 2>/dev/null || true)
    else
        RESULT=$(cat "$dockerfile" | $HADOLINT --format json - 2>/dev/null || true)
    fi

    if [ -z "$RESULT" ] || [ "$RESULT" = "[]" ] || [ "$RESULT" = "null" ]; then
        echo "  No findings."
        echo ""
        continue
    fi

    # Process with Python for filtering and mapping
    python3 - "$dockerfile" <<'PYEOF' "$RESULT"
import json
import sys

dockerfile = sys.argv[1]
raw = sys.argv[2]

try:
    findings = json.loads(raw)
except json.JSONDecodeError:
    print("  Failed to parse hadolint output")
    sys.exit(0)

if not isinstance(findings, list):
    findings = []

# Map hadolint rules to benchjack vulnerability classes
VULN_MAP = {
    "DL3002": ("V8", "HIGH", "Last USER should not be root"),
    "DL3004": ("V8", "MEDIUM", "Do not use sudo — agent may escalate privileges"),
    "DL3007": ("V8", "LOW", "Using :latest tag — unpinned base image"),
    "DL3025": ("V3", "LOW", "Use JSON notation for CMD/ENTRYPOINT — prevents shell injection"),
    "DL4006": ("V7", "LOW", "Missing pipefail — silent failures in evaluation scripts"),
}

# Additional patterns we check in the message text
KEYWORD_MAP = {
    "root": ("V8", "HIGH"),
    "sudo": ("V8", "MEDIUM"),
    "chmod 777": ("V8", "HIGH"),
    "COPY": ("V2", "LOW"),
}

benchjack_findings = []
other_findings = []

for f in findings:
    code = f.get("code", "")
    msg = f.get("message", "")
    line = f.get("line", 0)
    level = f.get("level", "info")

    if code in VULN_MAP:
        vuln, severity, desc = VULN_MAP[code]
        benchjack_findings.append({
            "vuln": vuln,
            "severity": severity,
            "rule": code,
            "line": line,
            "description": desc,
            "detail": msg,
        })
    else:
        other_findings.append({
            "rule": code,
            "line": line,
            "level": level,
            "message": msg,
        })

if benchjack_findings:
    print(f"  Benchmark-relevant findings: {len(benchjack_findings)}")
    for bf in benchjack_findings:
        print(f"    [{bf['vuln']}] {bf['severity']}: Line {bf['line']} ({bf['rule']})")
        print(f"      {bf['description']}")
        if bf['detail'] != bf['description']:
            print(f"      Detail: {bf['detail']}")
else:
    print("  No benchmark-relevant findings.")

if other_findings:
    print(f"  Other Dockerfile findings: {len(other_findings)}")
    for of in other_findings[:5]:
        print(f"    Line {of['line']} ({of['rule']}): {of['message']}")
    if len(other_findings) > 5:
        print(f"    ... and {len(other_findings) - 5} more")

print()
PYEOF

done

# Also scan for common anti-patterns in Dockerfiles that hadolint might miss
echo "--- Additional BenchJack Checks ---"
echo ""

for dockerfile in "${DOCKERFILES[@]}"; do
    echo "  Checking $dockerfile for benchmark-specific issues..."

    # Check for COPY of answer/test data
    if grep -inE "^(COPY|ADD).*\b(answer|gold|expected|reference|ground_truth|solution)\b" "$dockerfile" 2>/dev/null; then
        echo "    [V2] WARNING: Dockerfile copies answer/reference data into image"
    fi

    # Check for exposed agent ports without restriction
    EXPOSED=$(grep -ciE "^EXPOSE" "$dockerfile" 2>/dev/null || true)
    if [ "$EXPOSED" -gt 3 ] 2>/dev/null; then
        echo "    [V8] INFO: $EXPOSED ports exposed — broad network surface"
    fi

    # Check for world-writable permissions
    if grep -nE "chmod.*777" "$dockerfile" 2>/dev/null; then
        echo "    [V8] HIGH: World-writable permissions set in Dockerfile"
    fi

    # Check for --no-check-certificate or insecure fetches
    if grep -nE "(--no-check-certificate|--insecure|curl -k)" "$dockerfile" 2>/dev/null; then
        echo "    [V8] MEDIUM: Insecure download in Dockerfile — supply chain risk"
    fi

    # Check if final USER is non-root
    LAST_USER=$(grep -i "^USER " "$dockerfile" 2>/dev/null | tail -1 | awk '{print $2}' || true)
    if [ -z "$LAST_USER" ]; then
        echo "    [V8] MEDIUM: No USER directive — container runs as root by default"
    elif [ "$LAST_USER" = "root" ] || [ "$LAST_USER" = "0" ]; then
        echo "    [V8] HIGH: Final USER is root"
    fi

    echo ""
done

echo "[hadolint] Done."
