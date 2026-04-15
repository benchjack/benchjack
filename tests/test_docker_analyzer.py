"""Tests for .claude/skills/benchjack/tools/docker_analyzer.py."""

import pytest

from docker_analyzer import (
    Finding,
    analyze_compose,
    analyze_dockerfile,
    analyze_shell_scripts,
    find_compose_files,
    find_dockerfiles,
    find_shell_scripts,
)


# ── Finding ─────────────────────────────────────────────────────────

class TestDockerFinding:
    def test_to_dict(self):
        f = Finding("V8", "HIGH", "Dockerfile", 10, "runs as root", "USER root")
        d = f.to_dict()
        assert d["vuln_class"] == "V8"
        assert d["severity"] == "HIGH"
        assert d["line"] == 10

    def test_str(self):
        f = Finding("V1", "MEDIUM", "file.yml", 5, "rw mount", "evidence")
        s = str(f)
        assert "V1" in s
        assert "MEDIUM" in s


# ── find_* helpers ──────────────────────────────────────────────────

class TestFileFinders:
    def test_find_dockerfiles(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM ubuntu")
        (tmp_path / "Dockerfile.agent").write_text("FROM python")
        (tmp_path / "not_a_dockerfile.txt").write_text("nothing")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "test.dockerfile").write_text("FROM alpine")
        results = find_dockerfiles(str(tmp_path))
        assert len(results) == 3

    def test_find_compose_files(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "compose.yaml").write_text("version: '3'")
        (tmp_path / "random.yml").write_text("not compose")
        results = find_compose_files(str(tmp_path))
        assert len(results) == 2

    def test_find_shell_scripts(self, tmp_path):
        (tmp_path / "run.sh").write_text("#!/bin/bash")
        (tmp_path / "Makefile").write_text("all:")
        (tmp_path / "helper.py").write_text("import os")
        results = find_shell_scripts(str(tmp_path))
        assert len(results) == 3


# ── analyze_dockerfile ──────────────────────────────────────────────

class TestAnalyzeDockerfile:
    def test_no_user_directive(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nRUN apt-get update\n")
        findings = analyze_dockerfile(str(df))
        assert any(f.vuln_class == "V8" and "root by default" in f.message for f in findings)

    def test_user_root(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nUSER root\n")
        findings = analyze_dockerfile(str(df))
        assert any(f.vuln_class == "V8" and "root" in f.message.lower() for f in findings)

    def test_user_nonroot(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nUSER appuser\n")
        findings = analyze_dockerfile(str(df))
        # Should not flag V8 for non-root user
        assert not any("root" in f.message.lower() and "elevated" in f.message.lower() for f in findings)
        assert not any("root by default" in f.message for f in findings)

    def test_copy_answers(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nCOPY answer_key.json /data/\n")
        findings = analyze_dockerfile(str(df))
        assert any(f.vuln_class == "V2" for f in findings)

    def test_chmod_777(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nUSER app\nRUN chmod 777 /workspace\n")
        findings = analyze_dockerfile(str(df))
        assert any(f.vuln_class == "V8" and "World-writable" in f.message for f in findings)

    def test_many_ports(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nUSER app\nEXPOSE 8080 8081 8082 8083\n")
        findings = analyze_dockerfile(str(df))
        assert any("ports" in f.message.lower() for f in findings)

    def test_comment_lines_skipped(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\n# USER root\nUSER appuser\n")
        findings = analyze_dockerfile(str(df))
        assert not any("elevated" in f.message for f in findings)

    def test_unreadable_file(self, tmp_path):
        assert analyze_dockerfile(str(tmp_path / "nonexistent")) == []


# ── analyze_compose ─────────────────────────────────────────────────

class TestAnalyzeCompose:
    def test_privileged(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    privileged: true\n")
        findings = analyze_compose(str(cf))
        assert any(f.vuln_class == "V8" and f.severity == "CRITICAL" for f in findings)

    def test_host_network(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    network_mode: host\n")
        findings = analyze_compose(str(cf))
        assert any(f.vuln_class == "V8" and "host networking" in f.message for f in findings)

    def test_rw_volume(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    volumes:\n      - /data/answers:/workspace\n")
        findings = analyze_compose(str(cf))
        assert any(f.vuln_class == "V1" for f in findings)

    def test_ro_volume_no_v1(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    volumes:\n      - /code:/workspace:ro\n")
        findings = analyze_compose(str(cf))
        assert not any(f.vuln_class == "V1" for f in findings)

    def test_user_root(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    user: root\n")
        findings = analyze_compose(str(cf))
        assert any(f.vuln_class == "V8" and "root" in f.message for f in findings)

    def test_seccomp_unconfined(self, tmp_path):
        cf = tmp_path / "docker-compose.yml"
        cf.write_text("services:\n  agent:\n    security_opt:\n      - seccomp:unconfined\n")
        findings = analyze_compose(str(cf))
        assert any("security profile" in f.message.lower() for f in findings)


# ── analyze_shell_scripts ───────────────────────────────────────────

class TestAnalyzeShellScripts:
    def test_privileged(self, tmp_path):
        sh = tmp_path / "run.sh"
        sh.write_text("#!/bin/bash\ndocker run --privileged myimage\n")
        findings = analyze_shell_scripts(str(sh))
        assert any(f.vuln_class == "V8" and f.severity == "CRITICAL" for f in findings)

    def test_host_network(self, tmp_path):
        sh = tmp_path / "run.sh"
        sh.write_text("#!/bin/bash\ndocker run --network host myimage\n")
        findings = analyze_shell_scripts(str(sh))
        assert any("host networking" in f.message for f in findings)

    def test_cap_add(self, tmp_path):
        sh = tmp_path / "run.sh"
        sh.write_text("#!/bin/bash\ndocker run --cap-add SYS_ADMIN myimage\n")
        findings = analyze_shell_scripts(str(sh))
        assert any("cap-add" in f.message.lower() for f in findings)

    def test_rw_volume(self, tmp_path):
        sh = tmp_path / "run.sh"
        sh.write_text("#!/bin/bash\ndocker run -v /data:/workspace myimage\n")
        findings = analyze_shell_scripts(str(sh))
        assert any(f.vuln_class == "V1" for f in findings)

    def test_no_docker_no_findings(self, tmp_path):
        sh = tmp_path / "run.sh"
        sh.write_text("#!/bin/bash\necho hello\n")
        findings = analyze_shell_scripts(str(sh))
        assert findings == []
