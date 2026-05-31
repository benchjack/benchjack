"""
BenchJack audit pipeline package.

Re-exports the public API so callers can continue to use:
    from server.pipeline import AuditPipeline, HackPipeline, RefinePipeline, PHASES, ...
"""
from .audit import AuditPipeline
from .hack import HackPipeline
from .refine import RefinePipeline
from .models import (
    EXPLOIT_RESULT_JSONL,
    DEFAULT_REFINE_ROUNDS,
    HACK_PHASES,
    MAX_REFINE_ROUNDS,
    PHASES,
    REFINE_PHASES,
    TASK_IDS_JSON,
    TASK_RESULTS_JSONL,
    EmitFn,
    Finding,
    PhaseResult,
    clamp_refine_rounds,
    refine_phases,
)
from .utils import _derive_benchmark_name

__all__ = [
    "AuditPipeline",
    "HackPipeline",
    "RefinePipeline",
    "PHASES",
    "HACK_PHASES",
    "REFINE_PHASES",
    "DEFAULT_REFINE_ROUNDS",
    "MAX_REFINE_ROUNDS",
    "clamp_refine_rounds",
    "refine_phases",
    "Finding",
    "PhaseResult",
    "EmitFn",
    "TASK_RESULTS_JSONL",
    "EXPLOIT_RESULT_JSONL",
    "TASK_IDS_JSON",
    "_derive_benchmark_name",
]
