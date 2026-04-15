#!/usr/bin/env python3
"""
BenchJack Trust Boundary Mapper

Uses Python AST analysis to identify:
1. File reads/writes — who reads what, who writes what
2. Subprocess/exec calls — what runs where
3. Shared paths — paths both read by evaluator and writable by agent
4. Data flow from agent output into evaluator functions

Maps trust boundaries between agent and evaluator code to detect V1, V3, V7.

Usage: python3 trust_map.py <target-directory> [--eval-patterns PATTERN ...] [--agent-patterns PATTERN ...]
"""

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


# Default heuristics for classifying files as evaluator or agent code
EVAL_KEYWORDS = [
    "eval", "evaluate", "evaluator", "score", "scorer", "scoring",
    "grade", "grader", "grading", "judge", "judging",
    "validate", "validator", "validation", "metric", "metrics",
    "reward", "check", "checker", "verify", "verifier",
    "harness", "benchmark", "run_eval", "run_benchmark",
]

AGENT_KEYWORDS = [
    "agent", "model", "llm", "assistant", "solver", "solution",
    "inference", "predict", "generate", "response", "completion",
    "scaffold", "run_agent", "run_model",
]


class FileOperation:
    """Represents a file I/O operation found in source code."""
    def __init__(self, op_type, path_expr, source_file, line, context=""):
        self.op_type = op_type  # "read" or "write"
        self.path_expr = path_expr  # The path expression (may be variable)
        self.source_file = source_file
        self.line = line
        self.context = context  # "eval" or "agent" or "unknown"

    def to_dict(self):
        return vars(self)


class SubprocessCall:
    """Represents a subprocess/exec call found in source code."""
    def __init__(self, call_type, cmd_expr, source_file, line, shell=False, captures_output=False):
        self.call_type = call_type
        self.cmd_expr = cmd_expr
        self.source_file = source_file
        self.line = line
        self.shell = shell
        self.captures_output = captures_output

    def to_dict(self):
        return vars(self)


class DangerousSink:
    """Represents a dangerous function call (eval, exec, etc.)."""
    def __init__(self, sink_type, arg_expr, source_file, line):
        self.sink_type = sink_type
        self.arg_expr = arg_expr
        self.source_file = source_file
        self.line = line

    def to_dict(self):
        return vars(self)


class TrustAnalyzer(ast.NodeVisitor):
    """AST visitor that extracts file operations, subprocess calls, and dangerous sinks."""

    def __init__(self, source_file, context):
        self.source_file = source_file
        self.context = context  # "eval", "agent", or "unknown"
        self.file_ops = []
        self.subprocess_calls = []
        self.dangerous_sinks = []
        self._current_function = None

    def _expr_to_str(self, node):
        """Convert an AST expression to a readable string representation."""
        if node is None:
            return "<unknown>"
        try:
            return ast.unparse(node)
        except Exception:
            if isinstance(node, ast.Constant):
                return repr(node.value)
            elif isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Attribute):
                return f"{self._expr_to_str(node.value)}.{node.attr}"
            elif isinstance(node, ast.JoinedStr):
                return "f-string"
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                return "%-format"
            return "<complex-expr>"

    def visit_FunctionDef(self, node):
        old = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        func_name = self._get_func_name(node)

        # File reads
        if func_name in ("open", "builtins.open"):
            self._handle_open(node)
        elif func_name in ("pathlib.Path.read_text", "pathlib.Path.read_bytes",
                           "Path.read_text", "Path.read_bytes"):
            path_expr = self._expr_to_str(node.func.value) if isinstance(node.func, ast.Attribute) else "<unknown>"
            self.file_ops.append(FileOperation("read", path_expr, self.source_file, node.lineno, self.context))
        elif func_name in ("pathlib.Path.write_text", "pathlib.Path.write_bytes",
                           "Path.write_text", "Path.write_bytes"):
            path_expr = self._expr_to_str(node.func.value) if isinstance(node.func, ast.Attribute) else "<unknown>"
            self.file_ops.append(FileOperation("write", path_expr, self.source_file, node.lineno, self.context))
        elif func_name in ("json.load", "json.loads", "yaml.safe_load", "yaml.load",
                           "toml.load", "configparser.ConfigParser.read"):
            if node.args:
                path_expr = self._expr_to_str(node.args[0])
                self.file_ops.append(FileOperation("read", path_expr, self.source_file, node.lineno, self.context))
        elif func_name in ("json.dump", "yaml.dump", "toml.dump"):
            if len(node.args) >= 2:
                path_expr = self._expr_to_str(node.args[1])
                self.file_ops.append(FileOperation("write", path_expr, self.source_file, node.lineno, self.context))
        elif func_name in ("shutil.copy", "shutil.copy2", "shutil.move"):
            if len(node.args) >= 2:
                self.file_ops.append(FileOperation("read", self._expr_to_str(node.args[0]),
                                                   self.source_file, node.lineno, self.context))
                self.file_ops.append(FileOperation("write", self._expr_to_str(node.args[1]),
                                                   self.source_file, node.lineno, self.context))

        # Subprocess calls
        if func_name in ("subprocess.run", "subprocess.call", "subprocess.check_call",
                         "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
                         "subprocess.getstatusoutput"):
            cmd = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
            shell = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            captures = func_name in ("subprocess.check_output", "subprocess.getoutput",
                                     "subprocess.getstatusoutput") or any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "capture_output"
            )
            self.subprocess_calls.append(SubprocessCall(
                func_name, cmd, self.source_file, node.lineno, shell, captures
            ))
        elif func_name in ("os.system", "os.popen"):
            cmd = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
            self.subprocess_calls.append(SubprocessCall(
                func_name, cmd, self.source_file, node.lineno, shell=True, captures_output=(func_name == "os.popen")
            ))

        # Dangerous sinks (V3)
        if func_name in ("eval", "builtins.eval"):
            arg = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
            self.dangerous_sinks.append(DangerousSink("eval", arg, self.source_file, node.lineno))
        elif func_name in ("exec", "builtins.exec"):
            arg = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
            self.dangerous_sinks.append(DangerousSink("exec", arg, self.source_file, node.lineno))
        elif func_name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            arg = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
            self.dangerous_sinks.append(DangerousSink("pickle", arg, self.source_file, node.lineno))

        self.generic_visit(node)

    def _handle_open(self, node):
        """Determine if an open() call is a read or write."""
        path_expr = self._expr_to_str(node.args[0]) if node.args else "<unknown>"
        mode = "r"
        if len(node.args) > 1:
            mode_node = node.args[1]
            if isinstance(mode_node, ast.Constant):
                mode = str(mode_node.value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = str(kw.value.value)

        if any(c in mode for c in ("w", "a", "x", "+")):
            self.file_ops.append(FileOperation("write", path_expr, self.source_file, node.lineno, self.context))
        else:
            self.file_ops.append(FileOperation("read", path_expr, self.source_file, node.lineno, self.context))

    def _get_func_name(self, node):
        """Extract a dotted function name from a Call node."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return "<unknown>"


def classify_file(filepath, target, eval_patterns, agent_patterns):
    """Classify a Python file as evaluator code, agent code, or unknown."""
    rel = os.path.relpath(filepath, target).lower()
    parts = rel.replace(os.sep, "/").split("/")
    basename = os.path.basename(filepath).lower().replace(".py", "")

    # Check explicit patterns first
    for pat in eval_patterns:
        if re.search(pat, rel):
            return "eval"
    for pat in agent_patterns:
        if re.search(pat, rel):
            return "agent"

    # Heuristic classification
    all_parts = parts + [basename]
    eval_score = sum(1 for kw in EVAL_KEYWORDS if any(kw in p for p in all_parts))
    agent_score = sum(1 for kw in AGENT_KEYWORDS if any(kw in p for p in all_parts))

    if eval_score > agent_score:
        return "eval"
    elif agent_score > eval_score:
        return "agent"
    return "unknown"


def analyze_file(filepath, target, eval_patterns, agent_patterns):
    """Parse and analyze a single Python file."""
    context = classify_file(filepath, target, eval_patterns, agent_patterns)
    try:
        with open(filepath) as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return context, [], [], []

    analyzer = TrustAnalyzer(filepath, context)
    analyzer.visit(tree)
    return context, analyzer.file_ops, analyzer.subprocess_calls, analyzer.dangerous_sinks


def find_shared_paths(file_ops):
    """Find paths that are written in one context and read in another."""
    # Group by normalized path expression
    writes_by_context = defaultdict(set)  # context -> set of path_exprs
    reads_by_context = defaultdict(set)

    for op in file_ops:
        if op.op_type == "write":
            writes_by_context[op.context].add(op.path_expr)
        else:
            reads_by_context[op.context].add(op.path_expr)

    conflicts = []

    # Check: agent writes, evaluator reads
    agent_writes = writes_by_context.get("agent", set()) | writes_by_context.get("unknown", set())
    eval_reads = reads_by_context.get("eval", set()) | reads_by_context.get("unknown", set())

    # String-based overlap (exact match on path expressions)
    for path in agent_writes & eval_reads:
        conflicts.append({
            "type": "exact_match",
            "path": path,
            "risk": "Agent can write to a path the evaluator reads",
        })

    # Heuristic: look for common directory prefixes
    def extract_dir(expr):
        """Try to extract directory from path expression."""
        # Handle string literals
        m = re.search(r'["\']([^"\']+)["\']', expr)
        if m:
            return os.path.dirname(m.group(1))
        # Handle os.path.join
        m = re.search(r'os\.path\.join\(["\']([^"\']+)["\']', expr)
        if m:
            return m.group(1)
        return None

    agent_write_dirs = set()
    for p in agent_writes:
        d = extract_dir(p)
        if d:
            agent_write_dirs.add(d)

    eval_read_dirs = set()
    for p in eval_reads:
        d = extract_dir(p)
        if d:
            eval_read_dirs.add(d)

    for d in agent_write_dirs & eval_read_dirs:
        conflicts.append({
            "type": "shared_directory",
            "path": d,
            "risk": "Agent writes and evaluator reads from the same directory",
        })

    return conflicts


def main():
    parser = argparse.ArgumentParser(description="BenchJack Trust Boundary Mapper")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--eval-patterns", nargs="*", default=[],
                        help="Regex patterns to classify files as evaluator code")
    parser.add_argument("--agent-patterns", nargs="*", default=[],
                        help="Regex patterns to classify files as agent code")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    print("================================================================")
    print(" BenchJack Trust Boundary Mapper")
    print(f" Target: {target}")
    print("================================================================")
    print()

    # Find all Python files
    py_files = []
    for root, dirs, files in os.walk(target):
        # Skip common non-relevant directories
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv", ".tox")]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))

    print(f"[trust] Found {len(py_files)} Python file(s)")

    all_file_ops = []
    all_subprocess_calls = []
    all_dangerous_sinks = []
    file_contexts = {}

    for filepath in py_files:
        context, file_ops, subprocess_calls, dangerous_sinks = analyze_file(
            filepath, target, args.eval_patterns, args.agent_patterns
        )
        file_contexts[os.path.relpath(filepath, target)] = context
        all_file_ops.extend(file_ops)
        all_subprocess_calls.extend(subprocess_calls)
        all_dangerous_sinks.extend(dangerous_sinks)

    # Classify files summary
    ctx_counts = defaultdict(int)
    for ctx in file_contexts.values():
        ctx_counts[ctx] += 1
    print(f"[trust] Classification: {dict(ctx_counts)}")
    print()

    # --- Report: File Classification ---
    print("=== FILE CLASSIFICATION ===")
    for rel_path, ctx in sorted(file_contexts.items()):
        if ctx != "unknown":
            print(f"  [{ctx:>7}] {rel_path}")
    unknown_count = ctx_counts.get("unknown", 0)
    if unknown_count:
        print(f"  ... and {unknown_count} unclassified file(s)")
    print()

    # --- Report: File Operations ---
    print(f"=== FILE OPERATIONS ({len(all_file_ops)} total) ===")
    eval_reads = [op for op in all_file_ops if op.context == "eval" and op.op_type == "read"]
    eval_writes = [op for op in all_file_ops if op.context == "eval" and op.op_type == "write"]
    agent_reads = [op for op in all_file_ops if op.context == "agent" and op.op_type == "read"]
    agent_writes = [op for op in all_file_ops if op.context == "agent" and op.op_type == "write"]
    unknown_ops = [op for op in all_file_ops if op.context == "unknown"]

    print(f"  Evaluator reads:  {len(eval_reads)}")
    print(f"  Evaluator writes: {len(eval_writes)}")
    print(f"  Agent reads:      {len(agent_reads)}")
    print(f"  Agent writes:     {len(agent_writes)}")
    print(f"  Unknown context:  {len(unknown_ops)}")

    if eval_reads:
        print("\n  Key evaluator reads:")
        for op in eval_reads[:20]:
            print(f"    {op.source_file}:{op.line}  <- {op.path_expr}")

    if agent_writes:
        print("\n  Key agent writes:")
        for op in agent_writes[:20]:
            print(f"    {op.source_file}:{op.line}  -> {op.path_expr}")
    print()

    # --- Report: Shared Paths (V1) ---
    conflicts = find_shared_paths(all_file_ops)
    print(f"=== TRUST BOUNDARY CONFLICTS ({len(conflicts)}) ===")
    if conflicts:
        for c in conflicts:
            print(f"  [{c['type']}] {c['path']}")
            print(f"    Risk: {c['risk']}")
        print()
    else:
        print("  No obvious shared-path conflicts detected.")
        print("  Note: Dynamic paths and indirect references may not be detected.")
        print()

    # --- Report: Subprocess Calls ---
    print(f"=== SUBPROCESS CALLS ({len(all_subprocess_calls)} total) ===")
    for sc in all_subprocess_calls:
        flags = []
        if sc.shell:
            flags.append("SHELL")
        if sc.captures_output:
            flags.append("CAPTURES_OUTPUT")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        print(f"  {sc.source_file}:{sc.line}  {sc.call_type}({sc.cmd_expr}){flag_str}")
    print()

    # --- Report: Dangerous Sinks (V3) ---
    print(f"=== DANGEROUS SINKS ({len(all_dangerous_sinks)} total) ===")
    if all_dangerous_sinks:
        for ds in all_dangerous_sinks:
            print(f"  {ds.source_file}:{ds.line}  {ds.sink_type}({ds.arg_expr})")
    else:
        print("  No eval/exec/pickle calls found.")
    print()

    # --- Report: Findings Summary ---
    findings = []

    for c in conflicts:
        findings.append({
            "vulnerability": "V1",
            "severity": "HIGH",
            "message": f"Shared path: {c['path']} — {c['risk']}",
            "type": c["type"],
        })

    for ds in all_dangerous_sinks:
        findings.append({
            "vulnerability": "V3",
            "severity": "CRITICAL" if ds.sink_type in ("eval", "exec") else "HIGH",
            "message": f"{ds.sink_type}({ds.arg_expr}) at {ds.source_file}:{ds.line}",
            "file": ds.source_file,
            "line": ds.line,
        })

    # V7: evaluator captures subprocess output (from agent context)
    for sc in all_subprocess_calls:
        if sc.captures_output:
            findings.append({
                "vulnerability": "V7",
                "severity": "MEDIUM",
                "message": f"Evaluator captures output of {sc.call_type}({sc.cmd_expr}) — "
                           f"if this runs in agent context, output is untrusted",
                "file": sc.source_file,
                "line": sc.line,
            })

    print(f"=== FINDINGS SUMMARY ({len(findings)}) ===")
    by_vuln = defaultdict(list)
    for f in findings:
        by_vuln[f["vulnerability"]].append(f)

    for v in sorted(by_vuln):
        print(f"\n  {v}: {len(by_vuln[v])} finding(s)")
        for f in by_vuln[v]:
            print(f"    [{f['severity']}] {f['message']}")
    print()

    # Write structured output
    output = {
        "file_contexts": file_contexts,
        "file_operations": [op.to_dict() for op in all_file_ops],
        "subprocess_calls": [sc.to_dict() for sc in all_subprocess_calls],
        "dangerous_sinks": [ds.to_dict() for ds in all_dangerous_sinks],
        "trust_boundary_conflicts": conflicts,
        "findings": findings,
    }

    _results_dir = os.environ.get("BENCHJACK_RESULTS_DIR", "/tmp")
    output_path = os.path.join(_results_dir, "benchjack_trust_map.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[trust] Structured results written to {output_path}")


if __name__ == "__main__":
    main()
