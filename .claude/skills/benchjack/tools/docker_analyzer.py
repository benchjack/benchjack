#!/usr/bin/env python3
"""
BenchJack Docker Config Analyzer

Scans Dockerfiles, docker-compose.yml, and shell scripts for Docker
security issues relevant to benchmark hackability (V1, V8).

Usage: python3 docker_analyzer.py <target-directory>
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


class Finding:
    def __init__(self, vuln_class, severity, file, line, message, evidence=""):
        self.vuln_class = vuln_class
        self.severity = severity
        self.file = file
        self.line = line
        self.message = message
        self.evidence = evidence

    def to_dict(self):
        return vars(self)

    def __str__(self):
        loc = f"{self.file}:{self.line}" if self.line else self.file
        return f"  [{self.vuln_class}] {self.severity}: {loc}\n    {self.message}\n    > {self.evidence}"


def find_dockerfiles(target):
    """Find all Dockerfiles in the target directory."""
    patterns = ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
    results = []
    for root, _, files in os.walk(target):
        for f in files:
            name_lower = f.lower()
            if name_lower == "dockerfile" or name_lower.startswith("dockerfile.") or name_lower.endswith(".dockerfile"):
                results.append(os.path.join(root, f))
    return results


def find_compose_files(target):
    """Find all docker-compose files."""
    results = []
    for root, _, files in os.walk(target):
        for f in files:
            if f in ("docker-compose.yml", "docker-compose.yaml",
                     "compose.yml", "compose.yaml") or \
               f.startswith("docker-compose.") and (f.endswith(".yml") or f.endswith(".yaml")):
                results.append(os.path.join(root, f))
    return results


def find_shell_scripts(target):
    """Find shell scripts that might contain docker commands."""
    results = []
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith((".sh", ".bash")) or f in ("Makefile", "makefile"):
                results.append(os.path.join(root, f))
    # Also check .py files for subprocess docker calls
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith(".py"):
                results.append(os.path.join(root, f))
    return results


def analyze_dockerfile(filepath):
    """Analyze a Dockerfile for security issues."""
    findings = []
    try:
        with open(filepath) as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    has_user_directive = False
    last_user = None

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("#"):
            continue

        # V8: Running as root
        if stripped.upper().startswith("USER "):
            user = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else ""
            has_user_directive = True
            last_user = user
            if user in ("root", "0"):
                findings.append(Finding(
                    "V8", "HIGH", filepath, i,
                    "Container explicitly runs as root — agent has elevated privileges",
                    stripped
                ))

        # V1: COPY/ADD of test data or answers into agent image
        if stripped.upper().startswith(("COPY ", "ADD ")):
            lower = stripped.lower()
            for keyword in ["answer", "gold", "expected", "reference", "ground_truth", "solution", "test_data"]:
                if keyword in lower:
                    findings.append(Finding(
                        "V2", "MEDIUM", filepath, i,
                        f"COPY/ADD of file containing '{keyword}' — answers may be shipped in the image",
                        stripped
                    ))

        # V8: Installing sudo or granting broad permissions
        if "chmod 777" in stripped or "chmod -R 777" in stripped:
            findings.append(Finding(
                "V8", "MEDIUM", filepath, i,
                "World-writable permissions set — agent can modify any file",
                stripped
            ))

        if "apt" in stripped and "sudo" in stripped.split():
            findings.append(Finding(
                "V8", "LOW", filepath, i,
                "sudo installed in container — agent may escalate privileges",
                stripped
            ))

        # V8: Exposing many ports
        if stripped.upper().startswith("EXPOSE "):
            ports = stripped.split()[1:]
            if len(ports) > 3:
                findings.append(Finding(
                    "V8", "LOW", filepath, i,
                    f"Many ports exposed ({len(ports)}) — broad network surface for agent",
                    stripped
                ))

    # V8: No USER directive means running as root by default
    if not has_user_directive:
        findings.append(Finding(
            "V8", "MEDIUM", filepath, 0,
            "No USER directive — container runs as root by default",
            ""
        ))
    elif last_user in ("root", "0"):
        # Last USER is root, so final stage runs as root
        pass  # already flagged above

    return findings


def analyze_compose(filepath):
    """Analyze a docker-compose file for security issues."""
    findings = []
    try:
        with open(filepath) as f:
            content = f.read()
            lines = content.split("\n")
    except (OSError, UnicodeDecodeError):
        return findings

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # V8: privileged mode
        if "privileged:" in stripped and "true" in stripped.lower():
            findings.append(Finding(
                "V8", "CRITICAL", filepath, i,
                "Container runs in privileged mode — full host access, trivial escape",
                stripped
            ))

        # V8: network_mode host
        if "network_mode:" in stripped and "host" in stripped.lower():
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "Container uses host networking — agent can reach evaluator and host services",
                stripped
            ))

        # V8: cap_add
        if "cap_add:" in stripped or stripped.startswith("- SYS_") or stripped.startswith("- NET_") or stripped.startswith("- ALL"):
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "Extra Linux capabilities granted to container",
                stripped
            ))

        # V8: pid mode host
        if "pid:" in stripped and "host" in stripped.lower():
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "Container shares host PID namespace — can see/signal host processes",
                stripped
            ))

        # V1: Volume mounts
        if "volumes:" in stripped:
            # Flag the section; individual mounts analyzed below
            pass

        # V1: Specific volume mount analysis
        volume_match = re.match(r'^-\s+["\']?([^:]+):([^:"\']*)(?::([^"\']*))?["\']?', stripped)
        if volume_match:
            src, dst, mode = volume_match.group(1), volume_match.group(2), volume_match.group(3) or ""
            # Check for shared mounts
            if mode != "ro":
                findings.append(Finding(
                    "V1", "MEDIUM", filepath, i,
                    f"Read-write volume mount: {src} -> {dst}. If both agent and evaluator "
                    f"access this path, there is no filesystem isolation.",
                    stripped
                ))
            # Check for answer-containing paths
            lower_src = src.lower()
            for keyword in ["answer", "gold", "expected", "reference", "ground_truth", "data", "test"]:
                if keyword in lower_src:
                    findings.append(Finding(
                        "V2", "MEDIUM", filepath, i,
                        f"Volume mount of '{src}' — name suggests answer/test data accessible to agent",
                        stripped
                    ))
                    break

        # V8: user root
        if "user:" in stripped and ("root" in stripped or ": 0" in stripped or ":0" in stripped):
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "Container runs as root user",
                stripped
            ))

        # V8: security_opt apparmor/seccomp unconfined
        if "security_opt:" in stripped or "apparmor:unconfined" in stripped or "seccomp:unconfined" in stripped:
            if "unconfined" in stripped:
                findings.append(Finding(
                    "V8", "HIGH", filepath, i,
                    "Security profile disabled — container has unrestricted syscall access",
                    stripped
                ))

    return findings


def analyze_shell_scripts(filepath):
    """Analyze shell scripts and Python files for docker run commands."""
    findings = []
    try:
        with open(filepath) as f:
            content = f.read()
            lines = content.split("\n")
    except (OSError, UnicodeDecodeError):
        return findings

    # Join continuation lines for shell scripts
    if filepath.endswith((".sh", ".bash")) or filepath.split("/")[-1] in ("Makefile", "makefile"):
        joined = re.sub(r'\\\s*\n\s*', ' ', content)
        joined_lines = joined.split("\n")
    else:
        joined_lines = lines

    for i, line in enumerate(joined_lines, 1):
        if "docker" not in line.lower():
            continue

        # V8: --privileged
        if "--privileged" in line:
            findings.append(Finding(
                "V8", "CRITICAL", filepath, i,
                "docker run with --privileged — full host access",
                line.strip()[:200]
            ))

        # V8: --network host
        if "--network host" in line or "--net host" in line or "--network=host" in line or "--net=host" in line:
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "docker run with host networking",
                line.strip()[:200]
            ))

        # V8: --cap-add
        cap_match = re.search(r'--cap-add[= ](\S+)', line)
        if cap_match:
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                f"docker run with --cap-add {cap_match.group(1)}",
                line.strip()[:200]
            ))

        # V8: --user root or --user 0
        if "--user root" in line or "--user 0" in line or "--user=root" in line or "--user=0" in line:
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "docker run as root user",
                line.strip()[:200]
            ))

        # V8: --pid host
        if "--pid host" in line or "--pid=host" in line:
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "docker run with host PID namespace",
                line.strip()[:200]
            ))

        # V8: --security-opt with unconfined
        if "seccomp:unconfined" in line or "apparmor:unconfined" in line or "seccomp=unconfined" in line:
            findings.append(Finding(
                "V8", "HIGH", filepath, i,
                "docker run with security profile disabled",
                line.strip()[:200]
            ))

        # V1: Volume mounts
        vol_matches = re.finditer(r'-v\s+["\']?([^:\s]+):([^:\s"\']+)(?::([^\s"\']+))?', line)
        for m in vol_matches:
            src, dst, mode = m.group(1), m.group(2), m.group(3) or ""
            if mode != "ro":
                findings.append(Finding(
                    "V1", "MEDIUM", filepath, i,
                    f"Read-write volume mount: {src} -> {dst}",
                    line.strip()[:200]
                ))

        mount_matches = re.finditer(r'--mount\s+["\']?type=bind,source=([^,]+),target=([^,\s"\']+)(?:,readonly)?', line)
        for m in mount_matches:
            src, dst = m.group(1), m.group(2)
            if "readonly" not in m.group(0):
                findings.append(Finding(
                    "V1", "MEDIUM", filepath, i,
                    f"Read-write bind mount: {src} -> {dst}",
                    line.strip()[:200]
                ))

    return findings


def main():
    parser = argparse.ArgumentParser(description="BenchJack Docker Config Analyzer")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    print("================================================================")
    print(" BenchJack Docker Config Analyzer")
    print(f" Target: {target}")
    print("================================================================")
    print()

    all_findings = []

    # Scan Dockerfiles
    dockerfiles = find_dockerfiles(target)
    print(f"[docker] Found {len(dockerfiles)} Dockerfile(s)")
    for df in dockerfiles:
        findings = analyze_dockerfile(df)
        all_findings.extend(findings)

    # Scan docker-compose files
    compose_files = find_compose_files(target)
    print(f"[docker] Found {len(compose_files)} docker-compose file(s)")
    for cf in compose_files:
        findings = analyze_compose(cf)
        all_findings.extend(findings)

    # Scan shell scripts for docker commands
    shell_files = find_shell_scripts(target)
    docker_shell_files = []
    for sf in shell_files:
        try:
            with open(sf) as f:
                if "docker" in f.read().lower():
                    docker_shell_files.append(sf)
        except (OSError, UnicodeDecodeError):
            pass
    print(f"[docker] Found {len(docker_shell_files)} script(s) with docker commands")
    for sf in docker_shell_files:
        findings = analyze_shell_scripts(sf)
        all_findings.extend(findings)

    print()

    if not all_findings:
        print("[docker] No Docker-related findings.")
        if not dockerfiles and not compose_files:
            print("[docker] Note: No Docker configuration files found. The benchmark may not use Docker.")
        return

    # Group by vulnerability class
    by_vuln = {}
    for f in all_findings:
        by_vuln.setdefault(f.vuln_class, []).append(f)

    if args.json:
        output = {
            "total": len(all_findings),
            "findings_by_vulnerability": {
                k: [f.to_dict() for f in v] for k, v in sorted(by_vuln.items())
            }
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"[docker] Found {len(all_findings)} finding(s) across {len(by_vuln)} vulnerability class(es).\n")
        for vuln_class in sorted(by_vuln.keys()):
            findings = by_vuln[vuln_class]
            sev_counts = {}
            for f in findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            sev_str = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
            print(f"--- {vuln_class}: {len(findings)} finding(s) ({sev_str}) ---")
            for f in findings:
                print(f)
            print()

    # Write structured output
    _results_dir = os.environ.get("BENCHJACK_RESULTS_DIR", "/tmp")
    output_path = os.path.join(_results_dir, "benchjack_docker_results.json")
    with open(output_path, "w") as f:
        json.dump({
            "total": len(all_findings),
            "findings_by_vulnerability": {
                k: [fi.to_dict() for fi in v] for k, v in sorted(by_vuln.items())
            }
        }, f, indent=2)
    print(f"[docker] Structured results written to {output_path}")


if __name__ == "__main__":
    main()
