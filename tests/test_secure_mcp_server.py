import pytest
from airte.secure_mcp_server import (Principal, ToolPolicy, authorize,
                                     AuthorizationError, validate_path, validate_url)


def test_authorize_requires_scopes():
    p = Principal("svc", frozenset({"files:read"}))
    authorize(p, ToolPolicy("read_file", frozenset({"files:read"})))  # ok
    with pytest.raises(AuthorizationError):
        authorize(p, ToolPolicy("delete", frozenset({"files:write"})))


def test_path_confinement_blocks_traversal(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "ok.txt").write_text("hi")
    assert validate_path("ok.txt", str(root)).endswith("ok.txt")
    with pytest.raises(AuthorizationError):
        validate_path("../../etc/passwd", str(root))


def test_url_allowlist_and_metadata_block():
    with pytest.raises(AuthorizationError):
        validate_url("http://evil.com", frozenset({"api.example.com"}))
    with pytest.raises(AuthorizationError):
        validate_url("https://169.254.169.254", frozenset({"169.254.169.254"}))


def test_registry_enforces_authz_and_validation():
    from airte.secure_mcp_server.server import registry
    ops = Principal("ops-bot", frozenset({"ops:exec"}), tenant="ops")
    # missing scope -> denied
    nobody = Principal("nobody", frozenset())
    with pytest.raises(AuthorizationError):
        registry.invoke("run_named_command", nobody, command_name="uptime")
    # not allow-listed command -> validation error
    with pytest.raises(Exception):
        registry.invoke("run_named_command", ops, command_name="rm -rf /")
