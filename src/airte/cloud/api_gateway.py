"""Secure API-gateway configuration helpers for AI inference endpoints.

Encodes the controls you would terminate at an API gateway (AWS API Gateway /
Azure APIM / GCP API Gateway / Envoy) in front of an LLM endpoint: authN, per-
principal rate limiting, request-size caps, and content-type pinning. The
``validate_request`` function is a portable reference you can also run as an
in-app middleware.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GatewayPolicy:
    require_auth: bool = True
    allowed_content_types: frozenset[str] = field(
        default_factory=lambda: frozenset({"application/json"}))
    max_body_bytes: int = 256 * 1024          # cap prompt size (DoS / cost)
    rate_limit_per_min: int = 60
    burst: int = 10
    allowed_methods: frozenset[str] = field(
        default_factory=lambda: frozenset({"POST"}))


def build_rate_limit_policy(tier: str) -> GatewayPolicy:
    tiers = {
        "free":    GatewayPolicy(rate_limit_per_min=20, burst=5,
                                 max_body_bytes=64 * 1024),
        "pro":     GatewayPolicy(rate_limit_per_min=120, burst=20),
        "internal":GatewayPolicy(rate_limit_per_min=600, burst=60,
                                 max_body_bytes=1024 * 1024),
    }
    return tiers.get(tier, GatewayPolicy())


@dataclass
class _Request:
    method: str
    content_type: str
    body_bytes: int
    authenticated: bool


def validate_request(req: _Request, policy: GatewayPolicy) -> None:
    """Raise ValueError if the request violates the gateway policy."""
    if req.method not in policy.allowed_methods:
        raise ValueError(f"method {req.method} not allowed")
    if policy.require_auth and not req.authenticated:
        raise ValueError("unauthenticated request rejected at gateway")
    if req.content_type not in policy.allowed_content_types:
        raise ValueError(f"content-type {req.content_type} not allowed")
    if req.body_bytes > policy.max_body_bytes:
        raise ValueError(
            f"body {req.body_bytes}B exceeds cap {policy.max_body_bytes}B")
