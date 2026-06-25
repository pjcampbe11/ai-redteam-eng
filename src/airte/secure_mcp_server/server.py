"""Reference *hardened* MCP tool registry.

This is the secure counterpart to ``examples/vulnerable_mcp_server.py``. It is
transport-agnostic: the ``SecureToolRegistry`` wraps every tool call with

  1. authentication context (Principal)
  2. per-tool authorization (scoped permissions)
  3. input schema validation
  4. output redaction hook
  5. structured audit logging

To expose it over the real MCP stdio transport, install ``mcp`` and bind each
registered tool to ``@mcp.tool`` — the registry's ``invoke`` becomes the body.
The logic below runs and is unit-tested WITHOUT the mcp package installed.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .auth import (Principal, ToolPolicy, AuthorizationError, authorize,
                   validate_path, validate_url)

logger = logging.getLogger("airte.mcp.audit")


@dataclass
class RegisteredTool:
    name: str
    handler: Callable[..., Any]
    policy: ToolPolicy
    schema: dict[str, type]                  # arg name -> expected type
    redactor: Callable[[Any], Any] | None = None


class ValidationError(Exception):
    pass


@dataclass
class SecureToolRegistry:
    """A trust boundary around a set of MCP tools."""
    tools: dict[str, RegisteredTool] = field(default_factory=dict)
    _buckets: dict[tuple[str, str], list[float]] = field(default_factory=dict)

    def register(self, name: str, policy: ToolPolicy, schema: dict[str, type],
                 redactor: Callable[[Any], Any] | None = None):
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[name] = RegisteredTool(name, fn, policy, schema, redactor)
            return fn
        return deco

    # ---- core enforcement path -------------------------------------------
    def invoke(self, name: str, principal: Principal, **kwargs: Any) -> Any:
        started = time.time()
        tool = self.tools.get(name)
        if tool is None:
            self._audit(name, principal, "unknown_tool", started)
            raise ValidationError(f"no such tool: {name}")

        # 1. authorization (least privilege)
        try:
            authorize(principal, tool.policy)
        except AuthorizationError:
            self._audit(name, principal, "authz_denied", started)
            raise

        # 2. rate limiting (per principal+tool)
        self._enforce_rate_limit(tool, principal)

        # 3. input validation (type + presence)
        self._validate_input(tool, kwargs)

        # 4. execute
        result = tool.handler(principal=principal, **kwargs)

        # 5. output redaction
        if tool.redactor is not None:
            result = tool.redactor(result)

        self._audit(name, principal, "ok", started)
        return result

    # ---- internals --------------------------------------------------------
    def _validate_input(self, tool: RegisteredTool, kwargs: dict[str, Any]) -> None:
        for arg, expected in tool.schema.items():
            if arg not in kwargs:
                raise ValidationError(f"{tool.name}: missing argument '{arg}'")
            if not isinstance(kwargs[arg], expected):
                raise ValidationError(
                    f"{tool.name}: arg '{arg}' must be {expected.__name__}, "
                    f"got {type(kwargs[arg]).__name__}")
        extra = set(kwargs) - set(tool.schema)
        if extra:
            raise ValidationError(f"{tool.name}: unexpected args {sorted(extra)}")

    def _enforce_rate_limit(self, tool: RegisteredTool, principal: Principal) -> None:
        limit = tool.policy.rate_limit_per_min
        if not limit:
            return
        key = (tool.name, principal.subject)
        now = time.time()
        window = [t for t in self._buckets.get(key, []) if now - t < 60]
        if len(window) >= limit:
            raise AuthorizationError(
                f"rate limit exceeded for '{tool.name}' ({limit}/min)")
        window.append(now)
        self._buckets[key] = window

    def _audit(self, name: str, principal: Principal, outcome: str, started: float) -> None:
        logger.info(json.dumps({
            "event": "mcp_tool_call",
            "tool": name,
            "subject": principal.subject,
            "tenant": principal.tenant,
            "outcome": outcome,
            "latency_ms": round((time.time() - started) * 1000, 2),
        }))


# --------------------------------------------------------------------------
# Example: the SAME capabilities as the vulnerable server, done safely.
# --------------------------------------------------------------------------
registry = SecureToolRegistry()
FILE_ROOT = "/srv/mcp/data"
ALLOWED_HOSTS = frozenset({"api.example.com"})
ALLOWED_CMDS = {"status": ["systemctl", "is-active", "app"],
                "uptime": ["uptime"]}


@registry.register(
    "read_file",
    policy=ToolPolicy("read_file", required_scopes=frozenset({"files:read"}),
                      rate_limit_per_min=30),
    schema={"filename": str},
)
def read_file(principal: Principal, filename: str) -> str:
    safe = validate_path(filename, FILE_ROOT)   # confines to FILE_ROOT
    with open(safe, "r", encoding="utf-8") as fh:
        return fh.read()


@registry.register(
    "fetch_url",
    policy=ToolPolicy("fetch_url", required_scopes=frozenset({"net:egress"})),
    schema={"url": str},
)
def fetch_url(principal: Principal, url: str) -> str:
    validate_url(url, ALLOWED_HOSTS)             # anti-SSRF
    # import requests; return requests.get(url, allow_redirects=False, timeout=5).text
    return f"(would fetch validated url: {url})"


@registry.register(
    "run_named_command",
    policy=ToolPolicy("run_named_command",
                      required_scopes=frozenset({"ops:exec"}),
                      allow_tenants=frozenset({"ops"}),
                      rate_limit_per_min=5),
    schema={"command_name": str},
)
def run_named_command(principal: Principal, command_name: str) -> str:
    import subprocess
    argv = ALLOWED_CMDS.get(command_name)        # allow-list, no shell
    if argv is None:
        raise ValidationError(f"command '{command_name}' not allow-listed")
    return subprocess.run(argv, capture_output=True, text=True, shell=False).stdout
