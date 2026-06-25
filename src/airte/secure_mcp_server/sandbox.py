"""Sandboxed command execution for MCP tools that must shell out.

Provides defense-in-depth for the unavoidable case where a tool runs a
subprocess: command allow-listing (no shell), wall-clock timeout, output size
cap, a scrubbed environment (secrets stripped), and a confined working dir.

This is NOT a full isolation boundary — for untrusted code use a container,
gVisor/Firecracker microVM, or seccomp. It removes the easy footguns (shell
injection, env-var/secret leakage, runaway processes, output floods).
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


class SandboxError(Exception):
    pass


@dataclass
class Sandbox:
    allowed_commands: frozenset[str]
    timeout_seconds: float = 5.0
    max_output_bytes: int = 64 * 1024
    workdir: str | None = None
    # env vars allowed through; everything else (incl. secrets) is stripped
    env_allowlist: frozenset[str] = frozenset({"PATH", "LANG", "LC_ALL"})

    def run(self, argv: list[str]) -> str:
        if not argv:
            raise SandboxError("empty command")
        if argv[0] not in self.allowed_commands:
            raise SandboxError(f"command '{argv[0]}' not allow-listed")
        scrubbed_env = {k: v for k, v in os.environ.items()
                        if k in self.env_allowlist}
        try:
            proc = subprocess.run(
                argv,                       # list form => no shell, no injection
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                cwd=self.workdir,
                env=scrubbed_env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(
                f"command timed out after {self.timeout_seconds}s") from exc
        out = proc.stdout or ""
        if len(out.encode()) > self.max_output_bytes:
            out = out.encode()[:self.max_output_bytes].decode(errors="replace")
            out += "\n[truncated: output exceeded cap]"
        return out
