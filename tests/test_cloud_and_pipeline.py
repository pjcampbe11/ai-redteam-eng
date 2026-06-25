import os
import pytest
from airte.cloud import (SecretsManager, EnvSecretsProvider, get_model_key,
                         GatewayPolicy, validate_request, IdentityAwareProxy,
                         AccessRequest, ProxyDecision)
from airte.cloud.api_gateway import _Request
from airte.data_pipeline import (DLPEngine, scan_text, Classification,
                                 DataScope, evaluate_access, LeastPrivilegeError)
from airte.data_pipeline.least_privilege import AccessRequest as DReq


def test_secrets_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert get_model_key("anthropic_api_key") == "sk-test"
    assert "sk-test" not in repr(SecretsManager(EnvSecretsProvider()))


def test_gateway_rejects_oversized_body():
    pol = GatewayPolicy(max_body_bytes=10)
    with pytest.raises(ValueError):
        validate_request(_Request("POST", "application/json", 9999, True), pol)


def test_iap_step_up_for_confidential():
    iap = IdentityAwareProxy(model_access={"gpt": frozenset({"eng"})})
    req = AccessRequest("u", frozenset({"eng"}), "gpt",
                        data_classification="confidential", mfa_present=False)
    assert iap.authorize(req) is ProxyDecision.STEP_UP


def test_dlp_detects_and_redacts():
    findings = scan_text("SSN 123-45-6789 email a@b.com")
    labels = {f.label for f in findings}
    assert "us_ssn" in labels and "email" in labels
    redacted = DLPEngine().redact("SSN 123-45-6789")
    assert "123-45-6789" not in redacted


def test_least_privilege_blocks_cross_tenant():
    scope = DataScope(frozenset({"acme"}), Classification.CONFIDENTIAL)
    evaluate_access(scope, DReq("acme", Classification.INTERNAL, "support"))
    with pytest.raises(LeastPrivilegeError):
        evaluate_access(scope, DReq("other", Classification.INTERNAL, "support"))
    with pytest.raises(LeastPrivilegeError):
        evaluate_access(scope, DReq("acme", Classification.RESTRICTED, "support"))


def test_atlas_suite_builds():
    from airte.atlas import build_atlas_suite, map_owasp_to_atlas
    suite = build_atlas_suite()
    assert "AML.T0051" in suite and suite["AML.T0051"]
    assert map_owasp_to_atlas("LLM01")
