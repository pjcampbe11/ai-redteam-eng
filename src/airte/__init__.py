"""ai-redteam-eng: security engineering toolkit for AI pipelines, MCP
integrations, and agentic architectures.

Subpackages
-----------
- ``mcp_audit``        Static analysis for MCP server codebases.
- ``secure_mcp_server`` Reference hardened MCP server (authz, validation).
- ``redteam``          Adversarial test suites (prompt injection, jailbreak, ...).
- ``guardrails``       Runtime input/output/agent/RAG guardrails.
- ``cloud``            Secrets, API-gateway, identity-aware-proxy helpers.
- ``data_pipeline``    DLP, confidentiality boundaries, least privilege.
- ``atlas``            MITRE ATLAS TTP test harness.
"""

__version__ = "0.1.0"
