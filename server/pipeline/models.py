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

DEFAULT_REFINE_ROUNDS = 3
MAX_REFINE_ROUNDS = 10


def clamp_refine_rounds(value: int | str | None) -> int:
    """Normalize user-configured refine rounds to the supported range."""
    try:
        rounds = int(value) if value is not None else DEFAULT_REFINE_ROUNDS
    except (TypeError, ValueError):
        rounds = DEFAULT_REFINE_ROUNDS
    return min(max(rounds, 1), MAX_REFINE_ROUNDS)


def refine_phases(max_rounds: int | str | None = DEFAULT_REFINE_ROUNDS) -> list[tuple[str, str]]:
    rounds = clamp_refine_rounds(max_rounds)
    phases: list[tuple[str, str]] = []
    for n in range(1, rounds + 1):
        phases.append((f"r{n}_attack", f"Round {n} - Attack"))
        if n < rounds:
            phases.append((f"r{n}_patch", f"Round {n} - Patch"))
    return phases


REFINE_PHASES = refine_phases(DEFAULT_REFINE_ROUNDS)

TASK_RESULTS_JSONL = "benchjack_task_results.jsonl"
EXPLOIT_RESULT_JSONL = "exploit_result.jsonl"
TASK_IDS_JSON = "benchjack_task_ids.json"
