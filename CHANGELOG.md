# Changelog

All notable changes to **ai-redteam-eng** are documented here.
The project follows semantic-ish versioning aligned to the README roadmap.

## [0.4.0]
### Added
- Red-team targets for **Mistral**, **Cohere**, and **Ollama** (9 providers total)
  via `airte.redteam.build_target` with environment auto-detection.
- **CycloneDX VEX** layer (`airte.supply_chain.vex`): ref-validated vulnerability
  statements, `attach_vex`, `exploitable()`, and the `airte-vex` CLI.
- `security-scan.yml` workflow uploading the MCP scanner's SARIF to the Security tab.
### Fixed
- `ci.yml` red-team baseline no longer fails the build on the intentionally-weak
  `EchoTarget` (`--fail-on-asr 1.0`).

## [0.3.0]
### Added
- **Azure OpenAI** and **Google Vertex** red-team targets.
- ATLAS prompt-injection **sub-techniques**: `AML.T0051.000` (direct) and
  `AML.T0051.001` (indirect).
- **SARIF 2.1.0** output from the MCP scanner (`--format sarif`).
- `pre-commit` hooks (`airte-mcp-scan`, `airte-supply-audit`) + example config.

## [0.2.0]
### Added
- ATLAS **Reconnaissance** (`AML.T0040`) and **ML Attack Staging** (`AML.T0043`)
  tactics with `reconnaissance` / `attack_staging` suites.
- Live **Anthropic/OpenAI/Bedrock** targets and provider selection in `run_redteam`.
- **CycloneDX AI-BOM** exporter (`airte.supply_chain.aibom`).
- Optional **Presidio**-backed PII detection behind the DLP interface.

## [0.1.0]
### Added
- Initial release: MCP audit scanner, hardened MCP server, red-team harness
  (OWASP LLM Top 10 / MITRE ATLAS), runtime guardrails, cloud-security helpers,
  supply-chain auditing, DLP + least privilege, and the full docs set.
