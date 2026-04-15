"""Tests for server.pipeline.models — Finding, PhaseResult, constants."""

from server.pipeline.models import Finding, PhaseResult


class TestFinding:
    def test_new_generates_unique_ids(self):
        f1 = Finding.new(vulnerability="V1", severity="HIGH", title="t", description="d")
        f2 = Finding.new(vulnerability="V1", severity="HIGH", title="t", description="d")
        assert f1.id != f2.id

    def test_new_sets_fields(self):
        f = Finding.new(
            vulnerability="V3",
            severity="CRITICAL",
            title="eval injection",
            description="desc",
            file="score.py",
            line=42,
            evidence="eval(resp)",
        )
        assert f.vulnerability == "V3"
        assert f.severity == "CRITICAL"
        assert f.title == "eval injection"
        assert f.file == "score.py"
        assert f.line == 42
        assert f.evidence == "eval(resp)"
        assert f.source == "ai_analysis"  # default

    def test_new_defaults(self):
        f = Finding.new(vulnerability="V1", severity="HIGH", title="t", description="d")
        assert f.file == ""
        assert f.line == 0
        assert f.evidence == ""

    def test_id_length(self):
        f = Finding.new(vulnerability="V1", severity="HIGH", title="t", description="d")
        assert len(f.id) == 8


class TestPhaseResult:
    def test_defaults(self):
        pr = PhaseResult(phase="recon")
        assert pr.status == "pending"
        assert pr.findings == []
        assert pr.output == ""
        assert pr.summary == ""
        assert pr.duration == 0

    def test_findings_list_independence(self):
        """Each PhaseResult should have its own findings list."""
        pr1 = PhaseResult(phase="recon")
        pr2 = PhaseResult(phase="vuln_scan")
        pr1.findings.append(Finding.new(vulnerability="V1", severity="HIGH", title="t", description="d"))
        assert len(pr2.findings) == 0


