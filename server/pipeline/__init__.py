"""
BenchJack audit pipeline package.

Re-exports the public API so callers can continue to use:
    from server.pipeline import AuditPipeline, HackPipeline, PHASES, ...
"""
from .audit import AuditPipeline
from .hack import HackPipeline
from .models import (
    EXPLOIT_RESULT_JSONL,
    HACK_PHASES,
    PHASES,
    TASK_IDS_JSON,
    TASK_RESULTS_JSONL,
    EmitFn,
    Finding,
    PhaseResult,
)
from .utils import _derive_benchmark_name

__all__ = [
    "AuditPipeline",
    "HackPipeline",
    "PHASES",
    "HACK_PHASES",
    "Finding",
    "PhaseResult",
    "EmitFn",
    "TASK_RESULTS_JSONL",
    "EXPLOIT_RESULT_JSONL",
    "TASK_IDS_JSON",
    "_derive_benchmark_name",
]
