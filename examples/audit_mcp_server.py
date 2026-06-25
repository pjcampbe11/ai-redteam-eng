"""Example: programmatically audit an MCP server and gate on severity."""
from airte.mcp_audit import scan_path
from airte.mcp_audit.rules import Severity

findings = scan_path("examples/vulnerable_mcp_server.py")
critical = [f for f in findings if Severity[f.severity] >= Severity.HIGH]
print(f"{len(findings)} findings, {len(critical)} >= HIGH")
for f in critical:
    print(f"  {f.rule_id} {f.severity:8} {f.file}:{f.line} ({f.function})")
