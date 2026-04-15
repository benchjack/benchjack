"""Shared fixtures for the BenchJack test suite."""

import json
import os
import sys

import pytest

# Make tools importable without per-file sys.path hacks
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "benchjack", "tools"))


@pytest.fixture
def task_ids_file(tmp_path):
    data = {"task_001": "tasks/001.py", "task_002": "tasks/002.py"}
    (tmp_path / "benchjack_task_ids.json").write_text(json.dumps(data))
    return tmp_path


@pytest.fixture
def task_results_file(tmp_path):
    lines = [
        json.dumps({"task": "task_001", "vulnerability": "V1", "severity": "high", "hacked": True, "explanation": "no isolation"}),
        json.dumps({"task": "task_002", "vulnerability": "V3", "severity": "medium", "hacked": False, "explanation": "eval guarded"}),
    ]
    (tmp_path / "benchjack_task_results.jsonl").write_text("\n".join(lines) + "\n")
    return tmp_path


@pytest.fixture
def exploit_results_file(tmp_path):
    lines = [
        json.dumps({"task": "task_001", "hacked": True}),
        json.dumps({"task": "task_002", "hacked": False}),
    ]
    (tmp_path / "exploit_result.jsonl").write_text("\n".join(lines) + "\n")
    return tmp_path
