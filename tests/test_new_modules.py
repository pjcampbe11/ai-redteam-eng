import pytest


def test_new_redteam_suites_run():
    from airte.redteam import RedTeamHarness, EchoTarget
    for suite in ("unbounded_consumption", "supply_chain", "model_inversion"):
        report = RedTeamHarness(EchoTarget()).run(suite)
        assert report.total > 0
        assert {r.suite for r in report.results} == {suite}


def test_echo_target_trips_unbounded_and_backdoor():
    from airte.redteam import RedTeamHarness, EchoTarget
    report = RedTeamHarness(EchoTarget()).run("all")
    by_id = {r.case_id: r for r in report.results}
    assert by_id["UC-001"].succeeded      # output flood
    assert by_id["SC-001"].succeeded      # backdoor trigger 'tartan-7'


def test_atlas_full_coverage():
    from airte.atlas import build_atlas_suite, ATLAS_TTPS
    suite = build_atlas_suite()
    # every ATLAS technique now has runnable cases
    assert len(suite) == len(ATLAS_TTPS)
    assert all(cases for cases in suite.values())


def test_supply_chain_requirements_audit():
    from airte.supply_chain import audit_requirements
    findings = audit_requirements(
        "requests>=2.0\nflask==3.0.0\nfoo @ git+https://x/y.git\n")
    issues = {f.package: f.issue for f in findings}
    assert "requests" in issues          # unpinned
    assert "flask" not in issues         # pinned, clean
    assert any("URL/VCS" in i for i in issues.values())


def test_supply_chain_model_card_audit():
    from airte.supply_chain import audit_model_card
    bad = audit_model_card({"name": "m", "source": "random-hub"})
    assert any(f.field_name == "revision" for f in bad)   # no digest/revision
    good = audit_model_card({"name": "m", "source": "hf", "sha256": "ab12",
                             "trusted": True, "license": "apache-2.0"})
    assert good == []


def test_cost_tracker_enforces_caps():
    from airte.guardrails import CostTracker, BudgetExceeded
    t = CostTracker(max_tokens_per_window=1000)
    t.check_and_record("u", 600)
    with pytest.raises(BudgetExceeded):
        t.check_and_record("u", 600)     # 1200 > 1000
    assert t.usage("u")["tokens"] == 600


def test_sandbox_blocks_non_allowlisted_and_runs_allowed():
    from airte.secure_mcp_server import Sandbox, SandboxError
    sb = Sandbox(allowed_commands=frozenset({"echo"}))
    assert "hi" in sb.run(["echo", "hi"])
    with pytest.raises(SandboxError):
        sb.run(["rm", "-rf", "/"])


def test_sandbox_scrubs_secrets_from_env(monkeypatch):
    from airte.secure_mcp_server import Sandbox
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    sb = Sandbox(allowed_commands=frozenset({"printenv"}))
    # printenv of a non-allowlisted var returns empty (exit 1) -> scrubbed
    out = sb.run(["printenv"])
    assert "sk-secret" not in out


def test_provenance_detects_tampering():
    from airte.data_pipeline import SignedRecord, IntegrityError
    key = b"vault-key"
    rec = SignedRecord.create("trusted fact", "kb", key)
    rec.verify(key)                                   # ok
    tampered = SignedRecord(rec.data + " EVIL", rec.source, rec.tag)
    with pytest.raises(IntegrityError):
        tampered.verify(key)


def test_inmemory_secrets_provider():
    from airte.cloud import SecretsManager, InMemorySecretsProvider
    mgr = SecretsManager(InMemorySecretsProvider({"anthropic_api_key": "sk-x"}))
    assert mgr.get("anthropic_api_key") == "sk-x"
    assert "sk-x" not in repr(mgr)
