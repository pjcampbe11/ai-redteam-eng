"""Authorization, input validation and trust-boundary helpers for MCP servers.

These are framework-agnostic primitives you can drop into any MCP tool handler
to enforce the controls described in docs/mcp-security.md:

* per-principal, per-tool authorization (scoped permissions / least privilege)
* path confinement (defeats CWE-22 path traversal)
* URL allow-listing + metadata-endpoint blocking (defeats CWE-918 SSRF)
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class AuthorizationError(Exception):
    """Raised when a principal is not permitted to invoke a tool."""


@dataclass(frozen=True)
class Principal:
    """The authenticated caller behind an MCP session."""
    subject: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    tenant: str | None = None


@dataclass(frozen=True)
class ToolPolicy:
    """Declarative authorization policy for a single tool.

    ``required_scopes`` are ANDed: the principal must hold all of them.
    ``allow_tenants`` (if set) restricts which tenants may call the tool.
    """
    tool_name: str
    required_scopes: frozenset[str] = field(default_factory=frozenset)
    allow_tenants: frozenset[str] | None = None
    rate_limit_per_min: int | None = None


def authorize(principal: Principal, policy: ToolPolicy) -> None:
    """Raise AuthorizationError unless ``principal`` satisfies ``policy``."""
    missing = policy.required_scopes - principal.scopes
    if missing:
        raise AuthorizationError(
            f"principal '{principal.subject}' missing scopes for "
            f"'{policy.tool_name}': {sorted(missing)}"
        )
    if policy.allow_tenants is not None and principal.tenant not in policy.allow_tenants:
        raise AuthorizationError(
            f"tenant '{principal.tenant}' not permitted for '{policy.tool_name}'"
        )


def validate_path(user_path: str, root: str) -> str:
    """Confine ``user_path`` to ``root``. Returns a safe absolute path or raises.

    Defeats ``../`` traversal and absolute-path escape by resolving symlinks and
    asserting the result stays under the allow-listed root.
    """
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_real, user_path))
    if os.path.commonpath([root_real, candidate]) != root_real:
        raise AuthorizationError(f"path '{user_path}' escapes root '{root}'")
    return candidate


# RFC 1918 + link-local + loopback + cloud metadata
_BLOCKED_NETS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


def validate_url(url: str, allowed_hosts: frozenset[str],
                 allowed_schemes: frozenset[str] = frozenset({"https"})) -> str:
    """Validate an outbound URL for an MCP tool (anti-SSRF).

    * scheme must be allow-listed (default: https only)
    * host must be in ``allowed_hosts``
    * every resolved IP must be public (blocks metadata + RFC1918 ranges)
    """
    parsed = urlparse(url)
    if parsed.scheme not in allowed_schemes:
        raise AuthorizationError(f"scheme '{parsed.scheme}' not allowed")
    host = parsed.hostname or ""
    if host not in allowed_hosts:
        raise AuthorizationError(f"host '{host}' not in allow-list")
    if host in _METADATA_IPS:
        raise AuthorizationError("blocked cloud metadata endpoint")
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, parsed.port or 443):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip in _METADATA_IPS or any(ip in net for net in _BLOCKED_NETS):
            raise AuthorizationError(f"host '{host}' resolves to blocked IP {ip}")
    return url
