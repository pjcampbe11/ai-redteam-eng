"""Vulnerability rules used by the MCP audit scanner.

Each rule targets a dangerous *sink* (a function/attribute call) that is
commonly reachable from MCP tool handler input. The scanner performs lightweight
taint tracking from tool-handler parameters to these sinks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name


@dataclass(frozen=True)
class SinkRule:
    """A dangerous call pattern.

    ``dotted`` matches a fully/partially qualified call such as ``os.system``
    or ``subprocess.run``. ``names`` matches bare calls such as ``eval``.
    """
    id: str
    title: str
    severity: Severity
    cwe: str
    dotted: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    remediation: str = ""
    # kwargs that, when truthy, escalate risk (e.g. shell=True)
    danger_kwargs: tuple[str, ...] = field(default_factory=tuple)


RULES: list[SinkRule] = [
    SinkRule(
        id="AIRTE-MCP-001",
        title="OS command execution reachable from tool input",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        dotted=("os.system", "os.popen", "subprocess.run", "subprocess.call",
                "subprocess.Popen", "subprocess.check_output"),
        names=(),
        danger_kwargs=("shell",),
        remediation="Never pass tool arguments to a shell. Use argument lists "
                    "(shell=False), an allow-list of commands, and shlex.quote "
                    "for any unavoidable interpolation.",
    ),
    SinkRule(
        id="AIRTE-MCP-002",
        title="Dynamic code evaluation of tool input",
        severity=Severity.CRITICAL,
        cwe="CWE-95",
        names=("eval", "exec", "compile"),
        remediation="Remove eval/exec. Parse structured input explicitly "
                    "(json.loads, ast.literal_eval) and dispatch via a fixed map.",
    ),
    SinkRule(
        id="AIRTE-MCP-003",
        title="Insecure deserialization of tool input",
        severity=Severity.HIGH,
        cwe="CWE-502",
        dotted=("pickle.load", "pickle.loads", "yaml.load", "marshal.loads"),
        remediation="Use json or yaml.safe_load. Never unpickle untrusted data.",
    ),
    SinkRule(
        id="AIRTE-MCP-004",
        title="Unrestricted file access reachable from tool input (path traversal)",
        severity=Severity.HIGH,
        cwe="CWE-22",
        names=("open",),
        dotted=("pathlib.Path", "io.open"),
        remediation="Resolve the path and assert it is within an allow-listed "
                    "root (os.path.realpath + commonpath). Reject '..' segments.",
    ),
    SinkRule(
        id="AIRTE-MCP-005",
        title="Server-side request forgery via tool input",
        severity=Severity.HIGH,
        cwe="CWE-918",
        dotted=("requests.get", "requests.post", "requests.request",
                "urllib.request.urlopen", "httpx.get", "httpx.post"),
        remediation="Validate the URL against an allow-list of hosts/schemes, "
                    "block link-local/metadata ranges (169.254.169.254), and "
                    "disable redirects.",
    ),
    SinkRule(
        id="AIRTE-MCP-006",
        title="SQL string built from tool input",
        severity=Severity.HIGH,
        cwe="CWE-89",
        dotted=("cursor.execute", "cursor.executemany", "connection.execute"),
        remediation="Use parameterized queries (placeholders), never f-strings "
                    "or string concatenation for SQL.",
    ),
    SinkRule(
        id="AIRTE-MCP-007",
        title="Template rendered from tool input (SSTI)",
        severity=Severity.MEDIUM,
        cwe="CWE-1336",
        dotted=("Template", "jinja2.Template", "render_template_string"),
        remediation="Never build templates from input. Use a sandboxed "
                    "environment and pass input only as context variables.",
    ),
]
