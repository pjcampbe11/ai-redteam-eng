from pathlib import Path
from airte.mcp_audit import scan_path, MCPAuditScanner
from airte.mcp_audit.rules import Severity

VULN = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_mcp_server.py"


def test_scanner_flags_command_injection():
    findings = scan_path(VULN)
    ids = {f.rule_id for f in findings}
    assert "AIRTE-MCP-001" in ids  # os.popen / subprocess shell
    assert "AIRTE-MCP-002" in ids  # eval
    assert "AIRTE-MCP-006" in ids  # sql f-string


def test_taint_tracks_handler_argument():
    src = '''
def fetch_tool(url):
    import requests
    return requests.get(url).text
'''
    findings = MCPAuditScanner().scan_source(src, "t.py")
    assert any(f.rule_id == "AIRTE-MCP-005" for f in findings)
    ssrf = next(f for f in findings if f.rule_id == "AIRTE-MCP-005")
    assert ssrf.tainted_arg == "url"


def test_clean_handler_has_no_findings():
    src = '''
def safe_tool(name: str):
    allowed = {"a": 1, "b": 2}
    return allowed.get(name, 0)
'''
    assert MCPAuditScanner().scan_source(src, "ok.py") == []


def test_min_severity_filter():
    findings = scan_path(VULN, min_severity=Severity.CRITICAL)
    assert findings
    assert all(Severity[f.severity] >= Severity.CRITICAL for f in findings)
