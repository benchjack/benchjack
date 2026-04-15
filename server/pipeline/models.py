"""
Data models and shared constants for the audit pipeline.
"""
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine


@dataclass
class Finding:
    id: str
    vulnerability: str
    severity: str
    title: str
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    source: str = "ai_analysis"

    @staticmethod
    def new(**kwargs) -> "Finding":
        return Finding(id=uuid.uuid4().hex[:8], **kwargs)


@dataclass
class PhaseResult:
    phase: str
    status: str = "pending"
    findings: list[Finding] = field(default_factory=list)
    output: str = ""
    summary: str = ""
    duration: float = 0


EmitFn = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]

PHASES = [
    ("setup",     "Setup"),
    ("recon",     "Reconnaissance"),
    ("vuln_scan", "Vulnerability Scan"),
    ("poc",       "PoC Construction"),
    ("report",    "Report Generation"),
]

HACK_PHASES = [
    ("hack",   "Hack"),
    ("verify", "Verify & Improve"),
]

TASK_RESULTS_JSONL = "benchjack_task_results.jsonl"
EXPLOIT_RESULT_JSONL = "exploit_result.jsonl"
TASK_IDS_JSON = "benchjack_task_ids.json"
