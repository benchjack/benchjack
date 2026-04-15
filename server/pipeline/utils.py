"""
Utility functions for the audit pipeline:
  - benchmark name derivation
  - JSONL/JSON file readers
  - finding and task-result extractors
"""
import json
import os
import re

from .models import Finding, TASK_RESULTS_JSONL, TASK_IDS_JSON, EXPLOIT_RESULT_JSONL


def _parse_log_events(log_content: str, phase_id: str) -> list[dict]:
    """Parse a saved .log file back into a sequence of log event data dicts.

    The .log format (written by capturing_emit in the pipeline) is:
      [prompt]\\n...\\n[/prompt]        → msg_type "prompt"
      [tool: Name] summary text        → msg_type "tool_call"
      [result: N chars]                → msg_type "tool_result"
      anything else (possibly multi-line) → msg_type "text"
    """
    events: list[dict] = []
    text_buf: list[str] = []
    prompt_buf: list[str] | None = None  # non-None means inside a prompt block

    def _flush():
        text = "\n".join(text_buf).strip()
        text_buf.clear()
        if text:
            events.append({"phase": phase_id, "msg_type": "text", "text": text})

    for line in log_content.split("\n"):
        # Start of prompt block
        if line.rstrip() == "[prompt]" and prompt_buf is None:
            _flush()
            prompt_buf = []
            continue
        # End of prompt block
        if line.rstrip() == "[/prompt]" and prompt_buf is not None:
            events.append({
                "phase": phase_id,
                "msg_type": "prompt",
                "text": "\n".join(prompt_buf),
            })
            prompt_buf = None
            continue
        # Inside prompt block — collect lines
        if prompt_buf is not None:
            prompt_buf.append(line)
            continue

        if line.startswith("[tool: ") and "] " in line:
            _flush()
            after = line[len("[tool: "):]
            sep = after.index("] ")
            events.append({
                "phase": phase_id,
                "msg_type": "tool_call",
                "name": after[:sep],
                "summary": after[sep + 2:],
            })
        elif line.startswith("[result: ") and " chars]" in line:
            _flush()
            try:
                chars = int(line[len("[result: "):line.index(" chars]")])
            except ValueError:
                chars = 0
            events.append({"phase": phase_id, "msg_type": "tool_result", "chars": chars})
        else:
            text_buf.append(line)

    # Flush any unclosed prompt block as text
    if prompt_buf is not None:
        text_buf.extend(prompt_buf)
    _flush()
    return events


def _derive_benchmark_name(target: str) -> str:
    """Derive a filesystem-safe benchmark name from the target string."""
    target = target.strip().rstrip("/")
    if target.startswith(("http://", "https://")):
        name = target.split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
    elif "/" in target:
        # owner/repo slug — use repo part
        name = target.split("/")[-1]
    elif os.path.isdir(target):
        name = os.path.basename(os.path.abspath(target))
    else:
        name = target
    return re.sub(r"[^\w\-.]", "_", name)


def _read_task_ids_json(benchmark_path: str) -> dict[str, str]:
    """Read the task ID → path mapping written by the recon AI call.

    New format: JSON object  {"task_id": "path/to/definition", ...}
    Legacy format: JSON array ["task_id_1", "task_id_2", ...]  (path = "")

    Returns a dict mapping task ID → file path (empty string if unknown).
    """
    path = os.path.join(benchmark_path, TASK_IDS_JSON)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}

    # New format: plain dict of id → path
    if isinstance(data, dict):
        # Unwrap nested formats like {"task_ids": [...]} (legacy)
        for key in ("task_ids", "tasks", "ids"):
            if isinstance(data.get(key), list):
                return {str(x): "" for x in data[key] if x not in (None, "")}
        # Native new format: {id: path}
        return {str(k): str(v) for k, v in data.items() if k not in (None, "")}

    # Legacy format: plain array of IDs
    if isinstance(data, list):
        return {str(x): "" for x in data if x not in (None, "")}

    return {}


def _read_exploit_results(dir_path: str) -> list[dict]:
    """Read exploit results from exploit_result.jsonl in any directory.

    Returns a list of ``{"task": str, "hacked": bool}`` dicts.
    Works for both the benchmark repo directory and the hacks output directory.
    """
    path = os.path.join(dir_path, EXPLOIT_RESULT_JSONL)
    if not os.path.isfile(path):
        return []
    results: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                task = str(obj.get("task", "")).strip()
                if task:
                    results.append({"task": task, "hacked": bool(obj.get("hacked", False))})
            except (json.JSONDecodeError, AttributeError):
                continue
    return results


def _read_task_results_jsonl(
    benchmark_path: str, filename: str = TASK_RESULTS_JSONL
) -> list[dict]:
    """Read task results from a JSONL file written by the AI agent."""
    path = os.path.join(benchmark_path, filename)
    if not os.path.isfile(path):
        return []
    results: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append({
                    "task": str(obj.get("task", "")),
                    "vulnerability": str(obj.get("vulnerability", "")),
                    "severity": str(obj.get("severity", "")).upper(),
                    "hacked": bool(obj.get("hacked", False)),
                    "explanation": str(obj.get("explanation", "")),
                })
            except (json.JSONDecodeError, AttributeError):
                continue
    return results


def _parse_poc_status(text: str) -> str:
    """Parse the STATUS marker from a PoC evaluation response."""
    t = text.upper()
    if "### STATUS: ALL_HACKED" in t:
        return "all_hacked"
    if "### STATUS: CANNOT_HACK" in t:
        return "cannot_hack"
    return "retry"


def _expand_and_split_exploit_results(
    exploit_dir: str,
    task_ids_dir: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """Read exploit_result.jsonl and expand 'all_tasks' to real IDs when available.

    If any entry has task == 'all_tasks' and task_ids_dir contains a task-ID
    map, that entry is fanned out to one entry per real task ID.  Otherwise
    the 'all_tasks' entry is kept as-is (single row in the scoreboard).

    Returns:
        task_results — list of dicts suitable for ``task_result`` events
        exploit_list — list of ``{"task": str, "hacked": bool}`` for
                       the ``exploit_results`` event
    """
    raw = _read_task_results_jsonl(exploit_dir, EXPLOIT_RESULT_JSONL)
    if not raw:
        return [], []

    task_ids: dict[str, str] = {}
    if task_ids_dir:
        task_ids = _read_task_ids_json(task_ids_dir)

    task_results: list[dict] = []
    exploit_list: list[dict] = []

    for entry in raw:
        task = entry.get("task", "")
        if not task:
            continue
        if task == "all_tasks" and task_ids:
            for tid in task_ids:
                task_results.append({**entry, "task": tid})
                if entry.get("hacked"):
                    exploit_list.append({
                        "task": tid,
                        "hacked": True,
                        "vulnerability": entry.get("vulnerability", ""),
                        "severity": entry.get("severity", ""),
                        "explanation": entry.get("explanation", ""),
                    })
        else:
            task_results.append(entry)
            if entry.get("hacked"):
                exploit_list.append({
                    "task": task,
                    "hacked": True,
                    "vulnerability": entry.get("vulnerability", ""),
                    "severity": entry.get("severity", ""),
                    "explanation": entry.get("explanation", ""),
                })

    return task_results, exploit_list


def _extract_findings(text: str) -> list[Finding]:
    """Extract structured Finding objects from AI-generated text."""
    findings: list[Finding] = []
    for m in re.finditer(r"```finding\s*\n(.*?)```", text, re.DOTALL):
        try:
            obj = json.loads(m.group(1))
            findings.append(Finding.new(
                vulnerability=obj.get("vulnerability", "V?"),
                severity=obj.get("severity", "MEDIUM"),
                title=obj.get("title", ""),
                description=obj.get("description", ""),
                file=obj.get("file", ""),
                line=obj.get("line", 0),
                evidence=obj.get("evidence", ""),
            ))
        except (json.JSONDecodeError, KeyError):
            pass
    for m in re.finditer(
        r"###\s*FINDING\s*###\s*\n(.*?)###\s*END\s*FINDING\s*###",
        text, re.DOTALL,
    ):
        try:
            obj = json.loads(m.group(1))
            findings.append(Finding.new(
                vulnerability=obj.get("vulnerability", "V?"),
                severity=obj.get("severity", "MEDIUM"),
                title=obj.get("title", ""),
                description=obj.get("description", ""),
                file=obj.get("file", ""),
                line=obj.get("line", 0),
                evidence=obj.get("evidence", ""),
            ))
        except (json.JSONDecodeError, KeyError):
            pass
    return findings


def _extract_task_results_from_scripts(exec_results: list[dict]) -> list[dict]:
    """Parse per-task results from PoC script execution output.

    Scripts are named like ``poc_v1_isolation.py``.  Each script outputs
    lines such as ``task_001: PASS - exploited via …`` and a summary
    ``HACKED: X/Y tasks``.
    """
    task_results: list[dict] = []
    for result in exec_results:
        script = result.get("script", "")
        output = result.get("output", "")

        vuln_match = re.search(r"poc_v(\d+)", script, re.IGNORECASE)
        vuln = f"V{vuln_match.group(1)}" if vuln_match else None
        if not vuln:
            continue

        for line in output.splitlines():
            m = re.match(
                r"^\s*(.+?)[\s:]+\b(PASS|FAIL)\b[:\s\-]*(.*)",
                line,
                re.IGNORECASE,
            )
            if m:
                task_id = m.group(1).strip()
                if task_id.upper().startswith(("HACKED", "SUMMARY", "TOTAL")):
                    continue
                task_results.append({
                    "task": task_id,
                    "vulnerability": vuln,
                    "hacked": m.group(2).upper() == "PASS",
                    "explanation": m.group(3).strip(),
                })
    return task_results


def _extract_task_results_from_eval(text: str) -> list[dict]:
    """Parse structured ``task_results`` blocks from AI evaluation output."""
    results: list[dict] = []
    for m in re.finditer(r"```task_results\s*\n(.*?)```", text, re.DOTALL):
        try:
            items = json.loads(m.group(1))
            if isinstance(items, list):
                for item in items:
                    results.append({
                        "task": str(item.get("task", "")),
                        "vulnerability": str(item.get("vulnerability", "")),
                        "hacked": bool(item.get("hacked", False)),
                        "explanation": str(item.get("explanation", "")),
                    })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return results
