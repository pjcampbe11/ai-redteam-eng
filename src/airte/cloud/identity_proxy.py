"""Identity-aware-proxy (IAP) pattern for LLM access control.

Models the BeyondCorp / Cloudflare Access / GCP IAP style of authorization:
every request to the model endpoint carries a verified identity, and access is
decided per (user, model, action) against context (device posture, network,
data classification) — not network location.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ProxyDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up_auth"     # require re-auth / MFA


@dataclass(frozen=True)
class AccessRequest:
    user: str
    groups: frozenset[str]
    model: str
    data_classification: str = "public"     # public|internal|confidential|restricted
    device_compliant: bool = True
    mfa_present: bool = False


@dataclass
class IdentityAwareProxy:
    # which groups may use which models
    model_access: dict[str, frozenset[str]] = field(default_factory=dict)
    # classifications that always require MFA/step-up
    mfa_required_classifications: frozenset[str] = field(
        default_factory=lambda: frozenset({"confidential", "restricted"}))

    def authorize(self, req: AccessRequest) -> ProxyDecision:
        allowed_groups = self.model_access.get(req.model)
        if allowed_groups is None or req.groups.isdisjoint(allowed_groups):
            return ProxyDecision.DENY
        if not req.device_compliant:
            return ProxyDecision.DENY
        if req.data_classification in self.mfa_required_classifications and not req.mfa_present:
            return ProxyDecision.STEP_UP
        if req.data_classification == "restricted":
            # restricted data: only a dedicated group, even with MFA
            if "ai-restricted" not in req.groups:
                return ProxyDecision.DENY
        return ProxyDecision.ALLOW
