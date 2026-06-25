"""AST-based static analysis for MCP server codebases.

The scanner identifies functions that look like MCP tool handlers (decorated
with ``@mcp.tool``, ``@server.tool``, ``@tool``, or named ``*_tool`` /
``handle_*``) and performs lightweight taint tracking: any value derived from a
handler parameter that reaches a dangerous sink (see ``rules.py``) is flagged.

It is intentionally dependency-free so it can run in CI without installs:

    python -m airte.mcp_audit.scanner path/to/server.py
    python -m airte.mcp_audit.scanner src/ --format json --min-severity HIGH
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

from .rules import RULES, SinkRule, Severity

TOOL_DECORATORS = {"tool", "mcp_tool", "command", "resource"}
TOOL_NAME_HINTS = ("_tool", "handle_", "tool_", "_handler")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    file: str
    line: int
    col: int
    function: str
    snippet: str
    tainted_arg: str | None
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted call name, e.g. os.path.join -> 'os.path.join'."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _is_tool_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _dotted_name(target).split(".")[-1] if target else ""
        if name in TOOL_DECORATORS:
            return True
    return any(h in fn.name for h in TOOL_NAME_HINTS)


class _HandlerVisitor(ast.NodeVisitor):
    """Tracks variables tainted by handler parameters within one function."""

    def __init__(self, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                 source_lines: list[str], filename: str):
        self.fn = fn
        self.lines = source_lines
        self.filename = filename
        # seed taint set with the handler's parameters (skip self/cls/ctx)
        self.tainted: set[str] = set()
        for a in list(fn.args.args) + list(fn.args.kwonlyargs):
            if a.arg not in ("self", "cls", "ctx", "context"):
                self.tainted.add(a.arg)
        self.findings: list[Finding] = []

    # propagate taint across simple assignments: x = <tainted expr>
    def visit_Assign(self, node: ast.Assign) -> None:
        if self._expr_tainted(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.tainted.add(tgt.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sink(node)
        self.generic_visit(node)

    def _expr_tainted(self, node: ast.AST | None) -> str | None:
        """Return the name of a tainted source feeding this expression, if any."""
        for sub in ast.walk(node) if node is not None else []:
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return sub.id
            # f-strings / .format / % are common injection carriers
            if isinstance(sub, ast.JoinedStr):
                for v in sub.values:
                    if isinstance(v, ast.FormattedValue):
                        t = self._expr_tainted(v.value)
                        if t:
                            return t
        return None

    def _check_sink(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        bare = dotted.split(".")[-1]
        for rule in RULES:
            # Match the full dotted path or a dotted suffix (e.g. "requests.get"
            # or "client.requests.get"), or a bare builtin name. We do NOT match
            # on the trailing method alone -- that yields false positives for
            # common names like get/run/execute on unrelated objects.
            matched = (
                any(dotted == d or dotted.endswith("." + d) for d in rule.dotted)
                or bare in rule.names
            )
            if not matched:
                continue
            # find a tainted argument
            tainted_arg = None
            for arg in node.args:
                tainted_arg = self._expr_tainted(arg)
                if tainted_arg:
                    break
            if not tainted_arg:
                for kw in node.keywords:
                    tainted_arg = self._expr_tainted(kw.value)
                    if tainted_arg:
                        break
            # escalate: shell=True style danger kwargs
            danger = any(
                kw.arg in rule.danger_kwargs and _truthy(kw.value)
                for kw in node.keywords
            )
            # report if input reaches the sink, or a danger kwarg is set
            if tainted_arg or danger or (rule.id == "AIRTE-MCP-001" and not node.keywords and bare in ("system", "popen")):
                self.findings.append(self._make_finding(rule, node, tainted_arg, danger))
                break

    def _make_finding(self, rule: SinkRule, node: ast.Call,
                      tainted_arg: str | None, danger: bool) -> Finding:
        line = node.lineno
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        title = rule.title
        if danger and rule.danger_kwargs:
            title += f" ({rule.danger_kwargs[0]}=True)"
        return Finding(
            rule_id=rule.id,
            title=title,
            severity=str(rule.severity),
            cwe=rule.cwe,
            file=self.filename,
            line=line,
            col=node.col_offset,
            function=self.fn.name,
            snippet=snippet,
            tainted_arg=tainted_arg,
            remediation=rule.remediation,
        )


def _truthy(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and bool(node.value)


class MCPAuditScanner:
    def __init__(self, min_severity: Severity = Severity.INFO):
        self.min_severity = min_severity

    def scan_source(self, source: str, filename: str = "<string>") -> list[Finding]:
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:  # pragma: no cover
            return [Finding("AIRTE-MCP-000", f"Could not parse: {exc.msg}",
                            str(Severity.INFO), "N/A", filename,
                            exc.lineno or 0, 0, "<module>", "", None,
                            "Fix the syntax error and re-run.")]
        lines = source.splitlines()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_tool_handler(node):
                visitor = _HandlerVisitor(node, lines, filename)
                visitor.visit(node)
                findings.extend(visitor.findings)
        return [f for f in findings
                if Severity[f.severity] >= self.min_severity]

    def scan_file(self, path: Path) -> list[Finding]:
        return self.scan_source(path.read_text(encoding="utf-8"), str(path))


def scan_path(target: str | Path, min_severity: Severity = Severity.INFO) -> list[Finding]:
    scanner = MCPAuditScanner(min_severity=min_severity)
    target = Path(target)
    files: Iterable[Path]
    if target.is_dir():
        files = sorted(target.rglob("*.py"))
    else:
        files = [target]
    out: list[Finding] = []
    for f in files:
        out.extend(scanner.scan_file(f))
    return out


def _render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings. (Absence of findings is not proof of safety.)"
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(findings, key=lambda f: order.get(f.severity, 9))
    lines = [f"{len(findings)} finding(s):\n"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.rule_id} {f.title} ({f.cwe})")
        lines.append(f"    {f.file}:{f.line}  in {f.function}()")
        lines.append(f"    > {f.snippet}")
        if f.tainted_arg:
            lines.append(f"    tainted source: handler arg '{f.tainted_arg}'")
        lines.append(f"    fix: {f.remediation}\n")
    return "\n".join(lines)


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}


def _render_sarif(findings: list[Finding]) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning / CI integration."""
    # one rule per distinct rule_id encountered
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation or f.title},
                "helpUri": "https://cwe.mitre.org/data/definitions/"
                           + f.cwe.replace("CWE-", "") + ".html",
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")},
                "properties": {"tags": ["security", f.cwe],
                               "security-severity": {
                                   "CRITICAL": "9.5", "HIGH": "8.0",
                                   "MEDIUM": "5.0", "LOW": "3.0",
                                   "INFO": "1.0"}.get(f.severity, "5.0")},
            }
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. Tainted source: handler arg "
                                f"'{f.tainted_arg}'. {f.remediation}"
                                if f.tainted_arg else
                                f"{f.title}. {f.remediation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1),
                               "startColumn": max(f.col + 1, 1),
                               "snippet": {"text": f.snippet}},
                }}],
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "airte-mcp-audit",
                "informationUri": "https://github.com/pjcampbe11/ai-redteam-eng",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airte-scan",
                                 description="Audit MCP server code for injection sinks reachable from tool input.")
    ap.add_argument("target", help="Python file or directory to scan")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--min-severity", default="INFO",
                    choices=[s.name for s in Severity])
    ap.add_argument("--fail-on", default="HIGH",
                    choices=[s.name for s in Severity],
                    help="Exit non-zero if any finding >= this severity (CI gate).")
    args = ap.parse_args(argv)

    findings = scan_path(args.target, Severity[args.min_severity])
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "sarif":
        print(_render_sarif(findings))
    else:
        print(_render_text(findings))

    gate = Severity[args.fail_on]
    worst = max((Severity[f.severity] for f in findings), default=Severity.INFO)
    return 1 if worst >= gate else 0


if __name__ == "__main__":
    sys.exit(main())
