"""INTENTIONALLY VULNERABLE MCP server — DO NOT DEPLOY.

This file exists so the audit scanner has something to catch. Each handler
contains a textbook flaw that maps to a rule in airte.mcp_audit.rules.
Run:  python -m airte.mcp_audit.scanner examples/vulnerable_mcp_server.py
"""
import os
import pickle
import sqlite3
import subprocess

import requests  # noqa: F401  (optional; only needed to actually run)


# AIRTE-MCP-001: command injection via shell
def run_command_tool(command: str) -> str:
    # BUG: tool input goes straight to a shell
    return os.popen(command).read()


# AIRTE-MCP-001: subprocess with shell=True
def ping_host_tool(host: str) -> str:
    # BUG: shell=True + interpolated input
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout.decode()


# AIRTE-MCP-002: dynamic eval
def calculate_tool(expression: str) -> str:
    # BUG: eval on attacker-controlled string
    return str(eval(expression))


# AIRTE-MCP-003: insecure deserialization
def load_state_tool(blob: bytes):
    # BUG: unpickling untrusted bytes
    return pickle.loads(blob)


# AIRTE-MCP-004: path traversal
def read_file_tool(filename: str) -> str:
    # BUG: no path confinement
    with open(filename) as fh:
        return fh.read()


# AIRTE-MCP-005: SSRF
def fetch_url_tool(url: str) -> str:
    # BUG: no host allow-list, follows redirects
    return requests.get(url).text


# AIRTE-MCP-006: SQL injection
def lookup_user_tool(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # BUG: f-string SQL
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
