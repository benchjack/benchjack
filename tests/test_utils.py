"""Tests for server.pipeline.utils — pure utility functions."""

import json

import pytest

from server.pipeline.models import Finding
from server.pipeline.utils import (
    _derive_benchmark_name,
    _expand_and_split_exploit_results,
    _extract_findings,
    _extract_task_results_from_eval,
    _extract_task_results_from_scripts,
    _parse_log_events,
    _parse_poc_status,
    _read_exploit_results,
    _read_task_ids_json,
    _read_task_results_jsonl,
)


# ── _derive_benchmark_name ──────────────────────────────────────────

class TestDeriveBenchmarkName:
    def test_https_url(self):
        assert _derive_benchmark_name("https://github.com/org/my-bench.git") == "my-bench"

    def test_https_url_no_git(self):
        assert _derive_benchmark_name("https://github.com/org/my-bench") == "my-bench"

    def test_http_url(self):
        assert _derive_benchmark_name("http://example.com/repo") == "repo"

    def test_owner_repo_slug(self):
        assert _derive_benchmark_name("acme/benchmark-v2") == "benchmark-v2"

    def test_simple_name(self):
        assert _derive_benchmark_name("mybench") == "mybench"

    def test_trailing_slash_stripped(self):
        assert _derive_benchmark_name("https://github.com/org/repo/") == "repo"

    def test_whitespace_stripped(self):
        assert _derive_benchmark_name("  mybench  ") == "mybench"

    def test_special_chars_replaced(self):
        # Characters not matching [\w\-.]  become _
        assert _derive_benchmark_name("my bench!v2") == "my_bench_v2"

    def test_local_dir(self, tmp_path):
        # An existing directory uses its basename
        d = tmp_path / "my_benchmark"
        d.mkdir()
        assert _derive_benchmark_name(str(d)) == "my_benchmark"


# ── _parse_log_events ───────────────────────────────────────────────

class TestParseLogEvents:
    def test_text_only(self):
        log = "hello world\nsecond line"
        events = _parse_log_events(log, "recon")
        assert len(events) == 1
        assert events[0]["msg_type"] == "text"
        assert "hello world" in events[0]["text"]
        assert events[0]["phase"] == "recon"

    def test_tool_call(self):
        log = "[tool: Read] /some/file.py"
        events = _parse_log_events(log, "recon")
        assert len(events) == 1
        assert events[0]["msg_type"] == "tool_call"
        assert events[0]["name"] == "Read"
        assert events[0]["summary"] == "/some/file.py"

    def test_tool_result(self):
        log = "[result: 1234 chars]"
        events = _parse_log_events(log, "recon")
        assert len(events) == 1
        assert events[0]["msg_type"] == "tool_result"
        assert events[0]["chars"] == 1234

    def test_tool_result_bad_number(self):
        log = "[result: abc chars]"
        events = _parse_log_events(log, "recon")
        assert events[0]["chars"] == 0

    def test_prompt_block(self):
        log = "[prompt]\nDo the analysis\n[/prompt]"
        events = _parse_log_events(log, "vuln_scan")
        assert len(events) == 1
        assert events[0]["msg_type"] == "prompt"
        assert events[0]["text"] == "Do the analysis"

    def test_mixed(self):
        log = "intro\n[tool: Bash] ls\n[result: 50 chars]\nmore text"
        events = _parse_log_events(log, "recon")
        assert len(events) == 4
        types = [e["msg_type"] for e in events]
        assert types == ["text", "tool_call", "tool_result", "text"]

    def test_empty_string(self):
        assert _parse_log_events("", "x") == []

    def test_unclosed_prompt_becomes_text(self):
        log = "[prompt]\nsome prompt content\nno end tag"
        events = _parse_log_events(log, "x")
        assert len(events) == 1
        assert events[0]["msg_type"] == "text"
        assert "some prompt content" in events[0]["text"]


# ── _read_task_ids_json ─────────────────────────────────────────────

class TestReadTaskIdsJson:
    def test_new_format_dict(self, task_ids_file):
        result = _read_task_ids_json(str(task_ids_file))
        assert result == {"task_001": "tasks/001.py", "task_002": "tasks/002.py"}

    def test_legacy_format_list(self, tmp_path):
        (tmp_path / "benchjack_task_ids.json").write_text(
            json.dumps(["t1", "t2", "t3"])
        )
        result = _read_task_ids_json(str(tmp_path))
        assert result == {"t1": "", "t2": "", "t3": ""}

    def test_nested_task_ids_key(self, tmp_path):
        (tmp_path / "benchjack_task_ids.json").write_text(
            json.dumps({"task_ids": ["a", "b"]})
        )
        result = _read_task_ids_json(str(tmp_path))
        assert result == {"a": "", "b": ""}

    def test_missing_file(self, tmp_path):
        assert _read_task_ids_json(str(tmp_path)) == {}

    def test_invalid_json(self, tmp_path):
        (tmp_path / "benchjack_task_ids.json").write_text("not json")
        assert _read_task_ids_json(str(tmp_path)) == {}

    def test_filters_none_and_empty(self, tmp_path):
        (tmp_path / "benchjack_task_ids.json").write_text(
            json.dumps(["ok", None, ""])
        )
        result = _read_task_ids_json(str(tmp_path))
        assert result == {"ok": ""}


# ── _read_task_results_jsonl ────────────────────────────────────────

class TestReadTaskResultsJsonl:
    def test_reads_lines(self, task_results_file):
        results = _read_task_results_jsonl(str(task_results_file))
        assert len(results) == 2
        assert results[0]["task"] == "task_001"
        assert results[0]["hacked"] is True
        assert results[0]["severity"] == "HIGH"  # uppercased
        assert results[1]["hacked"] is False

    def test_missing_file(self, tmp_path):
        assert _read_task_results_jsonl(str(tmp_path)) == []

    def test_blank_lines_skipped(self, tmp_path):
        content = json.dumps({"task": "t1"}) + "\n\n" + json.dumps({"task": "t2"}) + "\n"
        (tmp_path / "benchjack_task_results.jsonl").write_text(content)
        results = _read_task_results_jsonl(str(tmp_path))
        assert len(results) == 2

    def test_bad_json_line_skipped(self, tmp_path):
        content = json.dumps({"task": "t1"}) + "\ngarbage\n" + json.dumps({"task": "t2"}) + "\n"
        (tmp_path / "benchjack_task_results.jsonl").write_text(content)
        results = _read_task_results_jsonl(str(tmp_path))
        assert len(results) == 2


# ── _read_exploit_results ───────────────────────────────────────────

class TestReadExploitResults:
    def test_reads_entries(self, exploit_results_file):
        results = _read_exploit_results(str(exploit_results_file))
        assert len(results) == 2
        assert results[0] == {"task": "task_001", "hacked": True}
        assert results[1] == {"task": "task_002", "hacked": False}

    def test_missing_file(self, tmp_path):
        assert _read_exploit_results(str(tmp_path)) == []

    def test_empty_task_skipped(self, tmp_path):
        content = json.dumps({"task": "", "hacked": True}) + "\n"
        (tmp_path / "exploit_result.jsonl").write_text(content)
        assert _read_exploit_results(str(tmp_path)) == []


# ── _parse_poc_status ───────────────────────────────────────────────

class TestParsePocStatus:
    def test_all_hacked(self):
        assert _parse_poc_status("blah ### STATUS: ALL_HACKED ### done") == "all_hacked"

    def test_cannot_hack(self):
        assert _parse_poc_status("### STATUS: CANNOT_HACK") == "cannot_hack"

    def test_retry(self):
        assert _parse_poc_status("some random output") == "retry"

    def test_case_insensitive(self):
        assert _parse_poc_status("### status: all_hacked") == "all_hacked"


# ── _extract_findings ───────────────────────────────────────────────

class TestExtractFindings:
    def test_fenced_block(self):
        text = '''Some intro text.
```finding
{"vulnerability": "V1", "severity": "HIGH", "title": "No isolation", "description": "Agent shares FS"}
```
More text.'''
        findings = _extract_findings(text)
        assert len(findings) == 1
        assert findings[0].vulnerability == "V1"
        assert findings[0].severity == "HIGH"
        assert findings[0].title == "No isolation"

    def test_hash_block(self):
        text = '''### FINDING ###
{"vulnerability": "V3", "severity": "CRITICAL", "title": "eval()", "description": "Eval on output"}
### END FINDING ###'''
        findings = _extract_findings(text)
        assert len(findings) == 1
        assert findings[0].vulnerability == "V3"

    def test_multiple(self):
        text = '''```finding
{"vulnerability": "V1", "severity": "HIGH", "title": "a", "description": "b"}
```
```finding
{"vulnerability": "V7", "severity": "MEDIUM", "title": "c", "description": "d"}
```'''
        findings = _extract_findings(text)
        assert len(findings) == 2

    def test_bad_json_skipped(self):
        text = '```finding\nnot json at all\n```'
        assert _extract_findings(text) == []

    def test_no_findings(self):
        assert _extract_findings("no findings here") == []

    def test_optional_fields(self):
        text = '''```finding
{"vulnerability": "V2", "severity": "LOW", "title": "t", "description": "d", "file": "x.py", "line": 10, "evidence": "ev"}
```'''
        f = _extract_findings(text)[0]
        assert f.file == "x.py"
        assert f.line == 10
        assert f.evidence == "ev"


# ── _extract_task_results_from_scripts ──────────────────────────────

class TestExtractTaskResultsFromScripts:
    def test_pass_and_fail(self):
        exec_results = [
            {
                "script": "poc_v1_isolation.py",
                "output": "task_001: PASS - exploited via shared fs\ntask_002: FAIL - could not exploit",
            },
        ]
        results = _extract_task_results_from_scripts(exec_results)
        assert len(results) == 2
        assert results[0]["task"] == "task_001"
        assert results[0]["hacked"] is True
        assert results[0]["vulnerability"] == "V1"
        assert results[1]["hacked"] is False

    def test_summary_lines_skipped(self):
        exec_results = [
            {
                "script": "poc_v3_eval.py",
                "output": "task_a: PASS - ok\nHACKED: 1/2 tasks\nTOTAL: 2",
            },
        ]
        results = _extract_task_results_from_scripts(exec_results)
        assert len(results) == 1
        assert results[0]["task"] == "task_a"

    def test_no_vuln_in_name_skipped(self):
        exec_results = [{"script": "unknown.py", "output": "task_001: PASS - ok"}]
        assert _extract_task_results_from_scripts(exec_results) == []


# ── _extract_task_results_from_eval ─────────────────────────────────

class TestExtractTaskResultsFromEval:
    def test_parses_block(self):
        text = '''```task_results
[{"task": "t1", "vulnerability": "V1", "hacked": true, "explanation": "shared fs"}]
```'''
        results = _extract_task_results_from_eval(text)
        assert len(results) == 1
        assert results[0]["task"] == "t1"
        assert results[0]["hacked"] is True

    def test_bad_json_skipped(self):
        text = '```task_results\nnot json\n```'
        assert _extract_task_results_from_eval(text) == []

    def test_no_block(self):
        assert _extract_task_results_from_eval("nothing here") == []


# ── _expand_and_split_exploit_results ───────────────────────────────

class TestExpandAndSplitExploitResults:
    def test_no_file(self, tmp_path):
        tr, el = _expand_and_split_exploit_results(str(tmp_path))
        assert tr == []
        assert el == []

    def test_normal_entries(self, tmp_path):
        lines = [
            json.dumps({"task": "t1", "vulnerability": "V1", "severity": "HIGH", "hacked": True, "explanation": "x"}),
            json.dumps({"task": "t2", "vulnerability": "V1", "severity": "HIGH", "hacked": False, "explanation": "y"}),
        ]
        (tmp_path / "exploit_result.jsonl").write_text("\n".join(lines) + "\n")
        tr, el = _expand_and_split_exploit_results(str(tmp_path))
        assert len(tr) == 2
        assert len(el) == 1  # only hacked=True
        assert el[0]["task"] == "t1"

    def test_all_tasks_expansion(self, tmp_path):
        # exploit_result.jsonl with "all_tasks" entry
        (tmp_path / "exploit_result.jsonl").write_text(
            json.dumps({"task": "all_tasks", "vulnerability": "V1", "severity": "HIGH", "hacked": True, "explanation": "x"}) + "\n"
        )
        # task_ids.json with real task IDs in a separate dir
        tid_dir = tmp_path / "tid"
        tid_dir.mkdir()
        (tid_dir / "benchjack_task_ids.json").write_text(
            json.dumps({"task_a": "a.py", "task_b": "b.py"})
        )
        tr, el = _expand_and_split_exploit_results(str(tmp_path), str(tid_dir))
        assert len(tr) == 2
        assert {r["task"] for r in tr} == {"task_a", "task_b"}
        assert len(el) == 2

    def test_all_tasks_no_expansion_without_ids(self, tmp_path):
        (tmp_path / "exploit_result.jsonl").write_text(
            json.dumps({"task": "all_tasks", "vulnerability": "V1", "severity": "HIGH", "hacked": True, "explanation": "x"}) + "\n"
        )
        tr, el = _expand_and_split_exploit_results(str(tmp_path))
        assert len(tr) == 1
        assert tr[0]["task"] == "all_tasks"
