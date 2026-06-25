import json
import subprocess
import sys
import os
import pytest


def _run(mod, *args):
    env = dict(os.environ, PYTHONPATH="src")
    return subprocess.run([sys.executable, "-m", mod, *args],
                          capture_output=True, text=True, env=env)


# --- Azure + Vertex targets ---
def test_azure_vertex_factory():
    from airte.redteam import build_target
    from airte.redteam.targets import AzureOpenAITarget, VertexTarget
    assert isinstance(build_target("azure"), AzureOpenAITarget)
    assert isinstance(build_target("azure-openai"), AzureOpenAITarget)
    assert isinstance(build_target("vertex"), VertexTarget)


# --- ATLAS PI sub-techniques ---
def test_pi_subtechniques():
    from airte.atlas import build_atlas_suite, ATLAS_TTPS
    suite = build_atlas_suite()
    assert len(suite["AML.T0051.000"]) == 4    # direct
    assert len(suite["AML.T0051.001"]) == 1    # indirect
    subs = {t.atlas_id: t.parent for t in ATLAS_TTPS if t.parent}
    assert subs["AML.T0051.000"] == "AML.T0051"
    assert subs["AML.T0051.001"] == "AML.T0051"


def test_direct_indirect_disjoint():
    from airte.redteam import prompt_injection as pi
    direct = {c.id for c in pi.direct_cases()}
    indirect = {c.id for c in pi.indirect_cases()}
    assert direct.isdisjoint(indirect)
    assert "PI-003" in indirect           # the RAG/indirect case


# --- SARIF output ---
def test_scanner_sarif_output():
    from airte.mcp_audit.scanner import scan_path, _render_sarif
    findings = scan_path("examples/vulnerable_mcp_server.py")
    sarif = json.loads(_render_sarif(findings))
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "airte-mcp-audit"
    assert driver["rules"] and sarif["runs"][0]["results"]
    # every result references a defined rule
    rule_ids = {r["id"] for r in driver["rules"]}
    assert all(res["ruleId"] in rule_ids for res in sarif["runs"][0]["results"])


def test_scanner_sarif_cli():
    r = _run("airte.mcp_audit.scanner",
             "examples/vulnerable_mcp_server.py", "--format", "sarif")
    doc = json.loads(r.stdout)
    assert doc["version"] == "2.1.0"


# --- supply-chain audit CLI (pre-commit entry) ---
def test_supply_audit_cli_exit_codes(tmp_path):
    clean = tmp_path / "requirements.txt"
    clean.write_text("flask==3.0.0\n")
    assert _run("airte.supply_chain.auditor", str(clean)).returncode == 0

    bad = tmp_path / "bad.txt"
    bad.write_text("foo @ git+https://x/y.git\n")
    assert _run("airte.supply_chain.auditor", str(bad)).returncode == 1


# --- pre-commit hook definitions exist and are well-formed ---
def test_precommit_hooks_defined():
    import pathlib, re
    text = pathlib.Path(".pre-commit-hooks.yaml").read_text()
    assert "id: airte-mcp-scan" in text
    assert "id: airte-supply-audit" in text
    assert "entry: airte-scan" in text
