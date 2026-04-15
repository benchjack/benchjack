"""Tests for .claude/skills/benchjack/tools/trust_map.py."""

import ast
import textwrap

import pytest

from trust_map import (
    DangerousSink,
    FileOperation,
    SubprocessCall,
    TrustAnalyzer,
    classify_file,
    find_shared_paths,
)


# ── classify_file ───────────────────────────────────────────────────

class TestClassifyFile:
    def test_eval_pattern_match(self, tmp_path):
        f = tmp_path / "custom_eval.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [r"custom_eval"], []) == "eval"

    def test_agent_pattern_match(self, tmp_path):
        f = tmp_path / "my_agent.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [], [r"my_agent"]) == "agent"

    def test_heuristic_eval(self, tmp_path):
        f = tmp_path / "scoring_module.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [], []) == "eval"

    def test_heuristic_agent(self, tmp_path):
        f = tmp_path / "agent_runner.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [], []) == "agent"

    def test_unknown(self, tmp_path):
        f = tmp_path / "utils.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [], []) == "unknown"

    def test_directory_path_keywords(self, tmp_path):
        d = tmp_path / "evaluator"
        d.mkdir()
        f = d / "main.py"
        f.write_text("")
        assert classify_file(str(f), str(tmp_path), [], []) == "eval"


# ── TrustAnalyzer ───────────────────────────────────────────────────

class TestTrustAnalyzer:
    def _analyze(self, code: str, context: str = "eval") -> TrustAnalyzer:
        tree = ast.parse(textwrap.dedent(code))
        analyzer = TrustAnalyzer("test.py", context)
        analyzer.visit(tree)
        return analyzer

    def test_open_read(self):
        a = self._analyze('f = open("data.json")')
        assert len(a.file_ops) == 1
        assert a.file_ops[0].op_type == "read"

    def test_open_write(self):
        a = self._analyze('f = open("out.txt", "w")')
        assert len(a.file_ops) == 1
        assert a.file_ops[0].op_type == "write"

    def test_open_append(self):
        a = self._analyze('f = open("log.txt", "a")')
        assert a.file_ops[0].op_type == "write"

    def test_open_mode_kwarg(self):
        a = self._analyze('f = open("f.txt", mode="w")')
        assert a.file_ops[0].op_type == "write"

    def test_json_load(self):
        a = self._analyze('import json\njson.load(open("x.json"))')
        # json.load and inner open both counted
        assert any(op.op_type == "read" for op in a.file_ops)

    def test_json_dump(self):
        a = self._analyze('import json\njson.dump(data, open("x.json", "w"))')
        assert any(op.op_type == "write" for op in a.file_ops)

    def test_subprocess_run(self):
        a = self._analyze('import subprocess\nsubprocess.run(["ls", "-la"])')
        assert len(a.subprocess_calls) == 1
        assert a.subprocess_calls[0].call_type == "subprocess.run"

    def test_subprocess_shell(self):
        a = self._analyze('import subprocess\nsubprocess.run("ls -la", shell=True)')
        assert a.subprocess_calls[0].shell is True

    def test_os_system(self):
        a = self._analyze('import os\nos.system("ls")')
        assert len(a.subprocess_calls) == 1
        assert a.subprocess_calls[0].shell is True

    def test_eval_sink(self):
        a = self._analyze('eval("2+2")')
        assert len(a.dangerous_sinks) == 1
        assert a.dangerous_sinks[0].sink_type == "eval"

    def test_exec_sink(self):
        a = self._analyze('exec("print(1)")')
        assert len(a.dangerous_sinks) == 1
        assert a.dangerous_sinks[0].sink_type == "exec"

    def test_pickle_load(self):
        a = self._analyze('import pickle\npickle.load(f)')
        assert len(a.dangerous_sinks) == 1
        assert a.dangerous_sinks[0].sink_type == "pickle"

    def test_shutil_copy(self):
        a = self._analyze('import shutil\nshutil.copy("src", "dst")')
        assert len(a.file_ops) == 2
        types = {op.op_type for op in a.file_ops}
        assert types == {"read", "write"}

    def test_context_propagated(self):
        a = self._analyze('f = open("x")', context="agent")
        assert a.file_ops[0].context == "agent"

    def test_check_output_captures(self):
        a = self._analyze('import subprocess\nsubprocess.check_output(["ls"])')
        assert a.subprocess_calls[0].captures_output is True

    def test_no_sinks_in_clean_code(self):
        a = self._analyze('x = 1 + 2\nprint(x)')
        assert a.dangerous_sinks == []
        assert a.subprocess_calls == []


# ── find_shared_paths ───────────────────────────────────────────────

class TestFindSharedPaths:
    def test_exact_match(self):
        ops = [
            FileOperation("write", '"output.json"', "agent.py", 10, "agent"),
            FileOperation("read", '"output.json"', "eval.py", 20, "eval"),
        ]
        conflicts = find_shared_paths(ops)
        assert len(conflicts) >= 1
        assert any(c["type"] == "exact_match" for c in conflicts)

    def test_no_conflict(self):
        ops = [
            FileOperation("write", '"a.json"', "agent.py", 10, "agent"),
            FileOperation("read", '"b.json"', "eval.py", 20, "eval"),
        ]
        conflicts = find_shared_paths(ops)
        assert not any(c["type"] == "exact_match" for c in conflicts)

    def test_shared_directory(self):
        ops = [
            FileOperation("write", 'os.path.join("/data", "out.json")', "agent.py", 10, "agent"),
            FileOperation("read", 'os.path.join("/data", "out.json")', "eval.py", 20, "eval"),
        ]
        conflicts = find_shared_paths(ops)
        assert any(c["type"] in ("exact_match", "shared_directory") for c in conflicts)

    def test_unknown_context_included(self):
        """Unknown context is included in both agent-write and eval-read sets."""
        ops = [
            FileOperation("write", '"shared.txt"', "unknown.py", 10, "unknown"),
            FileOperation("read", '"shared.txt"', "unknown.py", 20, "unknown"),
        ]
        conflicts = find_shared_paths(ops)
        # unknown writes ∩ unknown reads → should find exact match
        assert len(conflicts) >= 1


# ── Data classes ────────────────────────────────────────────────────

class TestDataClasses:
    def test_file_operation_to_dict(self):
        op = FileOperation("read", "/path", "file.py", 1, "eval")
        d = op.to_dict()
        assert d["op_type"] == "read"
        assert d["source_file"] == "file.py"

    def test_subprocess_call_to_dict(self):
        sc = SubprocessCall("subprocess.run", "ls", "file.py", 1, shell=True, captures_output=False)
        d = sc.to_dict()
        assert d["shell"] is True

    def test_dangerous_sink_to_dict(self):
        ds = DangerousSink("eval", "user_input", "file.py", 42)
        d = ds.to_dict()
        assert d["sink_type"] == "eval"
        assert d["line"] == 42
