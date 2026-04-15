"""
Global mutable state shared across the server lifetime.

Holds active run entries and the configuration set by create_app().
Imported by route modules to read/write shared state without circular imports.
"""
from typing import Any

# Each entry: {"bus": EventBus, "pipeline": ..., "sandbox": ..., "task": Task,
#              "target": str, "mode": "audit"|"hack"|"loaded"}
active_runs: dict[str, dict[str, Any]] = {}

# Set once by create_app() before any requests arrive.
ai_backend: str = "auto"
ai_model: str | None = None
use_sandbox: bool = True


def get_run(run_id: str) -> dict | None:
    return active_runs.get(run_id)


def run_is_active(run_id: str) -> bool:
    r = active_runs.get(run_id)
    return r is not None and r["task"] is not None and not r["task"].done()
