<div align="center">

# 🛡️ ai-redteam-eng

### Security engineering for AI pipelines, MCP integrations, and agentic architectures

*Design them securely. Break them deliberately. Harden them for production.*

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-55%20passing-brightgreen)
![Dependencies](https://img.shields.io/badge/core-dependency--free-success)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20TTPs-red)

</div>

---

This repository is part **field guide**, part **toolkit**. The [deep-dive docs](#-documentation)
explain *how* to secure each layer of an AI system; the `src/airte/` package gives you
**working, tested code** for the parts that need it — an MCP vulnerability scanner, a
reference hardened MCP server, an adversarial red-team harness mapped to MITRE ATLAS,
runtime guardrails, cloud-security helpers, supply-chain auditing, and data-pipeline DLP.

> [!WARNING]
> **Defensive security only.** The "offensive" code here exists to test and harden
> *your own* systems (red teaming), not to attack others. The deliberately vulnerable
> example server is a scanner target — **do not deploy it.**

---

## 📑 Table of Contents

1. [Why this exists](#-why-this-exists)
2. [Features](#-features)
3. [Architecture](#-architecture)
4. [Repository structure](#-repository-structure)
5. [Installation & quickstart](#-installation--quickstart)
6. [Section 1 — Model Context Protocol (MCP) security](#section-1--model-context-protocol-mcp-security)
7. [Section 2 — AI threat modeling](#section-2--ai-threat-modeling)
8. [Section 3 — AI system security: build / break / harden](#section-3--ai-system-security-build--break--harden)
9. [Section 4 — Cloud security for AI workloads](#section-4--cloud-security-for-ai-workloads)
10. [Section 5 — Securing agentic AI systems](#section-5--securing-agentic-ai-systems)
11. [Section 6 — Secure-by-default patterns](#section-6--secure-by-default-patterns)
12. [Section 7 — MCP security architecture review](#section-7--mcp-security-architecture-review)
13. [Section 8 — ATLAS threat modeling & red teaming](#section-8--atlas-threat-modeling--red-teaming)
14. [Section 9 — Securing data pipelines for AI](#section-9--securing-data-pipelines-for-ai)
15. [Section 10 — AI/ML supply chain security](#section-10--aiml-supply-chain-security)
16. [Module reference](#-module-reference)
17. [Usage recipes](#-usage-recipes)
18. [Testing & CI](#-testing--ci)
19. [Documentation](#-documentation)
20. [Roadmap](#-roadmap)
21. [References & license](#-references--license)

---

## 🎯 Why this exists

LLM and agentic systems break the usual security assumptions:

- **Natural-language input is also control flow.** A string can be data *or* an instruction.
- **Retrieved content can carry instructions.** Indirect prompt injection means the attacker is often not the user.
- **The model is a non-deterministic component an attacker can partly influence.**
- **Agents act in loops, with real permissions**, on state they partly control.

Classic AppSec is necessary but not sufficient. This repo packages the patterns and
tooling that actually hold up in production — architecture-first defenses, not just
detection heuristics that get bypassed.

---

## ✨ Features

| Capability | What you get |
|------------|--------------|
| 🔍 **MCP audit scanner** | AST taint-analysis flagging injection sinks (RCE, eval, deserialization, path traversal, SSRF, SQLi, SSTI) reachable from MCP tool input; **SARIF** output auto-uploaded to the Security tab via CI |
| 🧱 **Hardened MCP server** | Reference registry enforcing authN → authZ → rate limit → input validation → output redaction → audit, plus a sandboxed executor |
| ⚔️ **Red-team harness** | 9 adversarial suites (injection, jailbreak, poisoning, extraction, unbounded-consumption, supply-chain, inversion, reconnaissance, attack-staging) with ASR scoring, runnable against 9 providers (Anthropic/OpenAI/Bedrock/Azure/Vertex/Mistral/Cohere/Ollama) |
| 🛡️ **Runtime guardrails** | Input injection heuristics, output secret/PII redaction, RAG fencing/quarantine, agent scoped-permissions + HITL + budgets, token/cost caps |
| ☁️ **Cloud security** | Vault-backed secrets (AWS/Azure/GCP), API-gateway policy, identity-aware proxy, Terraform reference |
| 📦 **Supply-chain auditing** | Dependency-pinning & model-provenance checks; CycloneDX **AI-BOM** + **VEX** export; HMAC data integrity |
| 🗂️ **DLP & least privilege** | Sensitive-data detection/redaction (regex or optional **Presidio** ML backend) and per-user data-access scoping |
| 🎯 **MITRE ATLAS mapping** | 12 techniques across 8 tactics (incl. prompt-injection direct/indirect sub-techniques) mapped to runnable cases and the OWASP LLM Top 10 |
| 🪝 **Shift-left hooks** | `pre-commit` hooks bundling the MCP scanner + supply-chain audit |

---

## 🏗️ Architecture

The load-bearing idea is a **two-plane design**: the model is an *untrusted planner*
that emits proposals; a *deterministic control plane* validates and executes them
under the caller's permissions. Authority is enforced by the guard, never assumed
from the model's cooperation.

```
                    ┌─────────────────────────── REASONING PLANE (untrusted) ──┐
   user input ─►    │  prompt assembly  ─►  LLM / agent  ─►  proposed action    │
   retrieved  ─►    └───────────────▲───────────────────────────┬──────────────┘
   tool output       fence as DATA  │                           │ proposal
        │            (rag_guardrails)│                           ▼
        │                           │              ┌──────── ACTION PLANE (enforced) ───────┐
        ├─ scan_input (heuristics)  │              │  AgentGuard: scoped perms · HITL ·      │
        │                           │              │  step/cost budget                       │
        ▼                           │              │  SecureToolRegistry: authZ · validate · │
   DLP classify/redact ─────────────┘              │  rate-limit · sandbox · audit           │
   (data_pipeline.dlp)                             └───────────────┬─────────────────────────┘
                                                                   ▼
   output ◄─ redact_secrets ◄─ schema-validate ◄─ effect (file/db/network/tool)
```

Surrounding this: cloud controls (gateway rate/size caps, vault secrets, network
isolation, identity-aware proxy), supply-chain auditing on the way in, and a red-team
harness continuously validating the whole thing in CI.

---

## 📁 Repository structure

```
ai-redteam-eng/
├── README.md                       ← this file (single source of truth)
├── docs/                           ← deep dives (.md + .pdf, render on GitHub)
├── src/airte/
│   ├── mcp_audit/                  AST scanner for MCP server code (taint → sink)
│   ├── secure_mcp_server/          hardened MCP server + sandboxed executor
│   ├── redteam/                    9 adversarial suites + harness + live targets
│   ├── guardrails/                 input/output/agent/RAG guardrails + cost budget
│   ├── cloud/                      secrets (AWS/Azure/GCP), API gateway, IAP
│   ├── data_pipeline/              DLP + least-privilege + data provenance
│   ├── supply_chain/               dependency + model-card auditing + AI-BOM (LLM03)
│   └── atlas/                      MITRE ATLAS TTP suite + OWASP mapping
├── examples/                       vulnerable server, live red-team, audits
├── iac/terraform/aws-ai-gateway/   secure-by-default cloud reference (Terraform)
├── tests/                          pytest suite (33 tests, runs offline)
└── .github/workflows/ci.yml        CI: tests + scan gate + red-team regression
```

---

## 🚀 Installation & quickstart

```bash
git clone https://github.com/<you>/ai-redteam-eng.git
cd ai-redteam-eng
python -m pip install -e ".[dev]"          # core is dependency-free; this adds pytest

# 1) Audit an MCP server for injection sinks reachable from tool input
python -m airte.mcp_audit.scanner examples/vulnerable_mcp_server.py --fail-on HIGH
python -m airte.mcp_audit.scanner src/ --format sarif > airte.sarif   # for code scanning

# 2) Red-team a target (EchoTarget demo, or a live model) → attack-success-rate
python -m airte.redteam.harness --suite all
python examples/run_redteam.py --provider openai   # +bedrock|azure|vertex|mistral|cohere|ollama

# 3) See MITRE ATLAS coverage of the bundled adversarial cases
python -m airte.atlas.ttp_suite

# 4) Audit your supply chain
python -m pytest -q                         # 55 tests, no network, no API keys
```

> The core library imports nothing outside the Python 3.10+ standard library, so the
> scanner, harness, guardrails, and auditors run in CI with zero install friction.
> Optional extras (live LLM clients, the `mcp` SDK, cloud SDKs) are only needed for
> the live integrations.

---

## Section 1 — Model Context Protocol (MCP) security

**📄 Deep dive:** [`docs/mcp-security.md`](docs/mcp-security.md) · [PDF](docs/mcp-security.pdf)

### What MCP is

The Model Context Protocol is an open protocol standardizing how applications give
LLMs context and capabilities. It defines a **client–server** architecture: a *host*
(IDE, chat client, agent runtime) runs *MCP clients*, each holding a 1:1 connection to
an *MCP server*. Servers expose **tools** (callable functions), **resources**
(read-only context), and **prompts** (templates). Messages are JSON-RPC 2.0 over a
transport — **stdio** (host launches the server as a subprocess; inherits local
privileges) or **streamable HTTP/SSE** (network service; needs its own authN/Z). The
transport choice is a primary security decision.

### How servers are structured & how tools reach the model

```
initialize            → negotiate protocol version + capabilities
tools/list            → server returns tool definitions (name, description, inputSchema)
tools/call            → host asks server to execute a tool with arguments
resources/list, read  → server advertises and serves read-only context
prompts/list, get     → server advertises reusable prompt templates
```

`tools/list` returns, per tool, a `name`, a natural-language `description`, and a JSON
`inputSchema`. The host injects these into the model's context. Two consequences:

1. **The description is attack surface.** A malicious/compromised server can embed
   injection payloads in tool descriptions ("tool poisoning") that hijack the model.
2. **Schema is advisory, not enforcement.** The model is *asked* to conform; the
   server must validate every argument itself. **Treat every tool argument as
   untrusted input crossing a trust boundary** — it is ultimately chosen by a model an
   attacker may influence.

### Auditing for injection vulnerabilities

The pattern to hunt: *does a value derived from a tool argument reach a dangerous sink
without validation?* This repo ships an AST scanner that does exactly this taint
analysis.

| Sink | Class | CWE | Rule |
|------|-------|-----|------|
| `os.system`, `subprocess(shell=True)` | Command injection | CWE-78 | AIRTE-MCP-001 |
| `eval`, `exec`, `compile` | Code injection | CWE-95 | AIRTE-MCP-002 |
| `pickle.loads`, `yaml.load` | Insecure deserialization | CWE-502 | AIRTE-MCP-003 |
| `open`, raw path joins | Path traversal | CWE-22 | AIRTE-MCP-004 |
| `requests.get(user_url)` | SSRF (cloud metadata!) | CWE-918 | AIRTE-MCP-005 |
| f-string SQL → `cursor.execute` | SQL injection | CWE-89 | AIRTE-MCP-006 |
| `Template(user_input)` | SSTI | CWE-1336 | AIRTE-MCP-007 |

```bash
python -m airte.mcp_audit.scanner path/to/server.py --fail-on HIGH
```

It identifies tool handlers (by `@tool`-style decorators or `*_tool`/`handle_*`
naming), seeds taint from handler parameters, propagates through assignments and
f-strings, and reports when tainted data reaches a sink.
`examples/vulnerable_mcp_server.py` is a labeled corpus of each bug class. Use
`--format sarif` to emit SARIF 2.1.0 for GitHub code scanning, and the bundled
`pre-commit` hooks (`airte-mcp-scan`, `airte-supply-audit`) to shift these checks
left into every commit.

### Secure enterprise deployment patterns

Pin & vet servers (supply chain) · least privilege per server · authenticated sessions
with per-tool authorization · validate/confine inputs (schema, path confinement, URL
allow-listing + metadata blocking) · sandbox the runtime, deny egress by default ·
human-in-the-loop for high-risk tools · centralized audit logging · treat tool
descriptions as code. `airte.secure_mcp_server.SecureToolRegistry` wires all of this
into one enforced path.

---

## Section 2 — AI threat modeling

**📄 Deep dive:** [`docs/threat-modeling.md`](docs/threat-modeling.md) · [PDF](docs/threat-modeling.pdf)

Threat modeling for AI asks the classic four questions over a system whose trust
boundaries are unusual: natural-language input is control flow, retrieved data carries
instructions, and the model is a partly-attacker-influenced component. The method:
diagram data/trust flows (mark every place untrusted text enters context), enumerate
the model's blast radius (every tool/action it can trigger), apply STRIDE **plus** the
OWASP LLM Top 10 and ATLAS, and rank by realistic impact.

### OWASP Top 10 for LLM Applications (2025)

| ID | Risk | One-line threat |
|----|------|-----------------|
| **LLM01** | Prompt Injection | Crafted input (direct or via retrieved content) subverts instructions. |
| **LLM02** | Sensitive Information Disclosure | Model leaks PII, secrets, or proprietary data. |
| **LLM03** | Supply Chain | Compromised models, datasets, plugins, or MCP servers. |
| **LLM04** | Data and Model Poisoning | Tampered training/fine-tune/RAG data alters behavior. |
| **LLM05** | Improper Output Handling | Downstream system trusts model output (XSS/SSRF/RCE). |
| **LLM06** | Excessive Agency | Model has too much permission/autonomy; actions run unchecked. |
| **LLM07** | System Prompt Leakage | Hidden instructions/secrets in the system prompt are exposed. |
| **LLM08** | Vector and Embedding Weaknesses | RAG/embedding poisoning, inversion, cross-tenant leakage. |
| **LLM09** | Misinformation | Confident, wrong output; over-reliance without verification. |
| **LLM10** | Unbounded Consumption | Resource/cost exhaustion, denial of wallet, model DoS. |

### Adversarial ML techniques (with runnable suites)

- **Prompt injection** (LLM01 / ATLAS AML.T0051) — direct (`.000`) in user input;
  indirect (`.001`) hidden in retrieved content. Indirect is the dangerous variant.
- **Jailbreaking** (ATLAS AML.T0054) — persona, hypothetical framing, refusal
  suppression, payload splitting. Targets the *policy* layer.
- **Data poisoning** (LLM04 / ATLAS AML.T0020) — planted facts/backdoors in
  training, fine-tune, or RAG data.
- **Model extraction / inversion** (LLM02/LLM07 / ATLAS AML.T0024, T0056, T0048) —
  steal the system prompt, recover memorized secrets, reconstruct training data.

### Mitigations that hold up in production

> [!IMPORTANT]
> There is **no reliable, complete prompt-injection filter.** Heuristic classifiers
> (this repo ships one) reduce noise but are bypassable. Production resilience comes
> from **architecture**, not detection.

Privilege separation / least agency (LLM06) · treat retrieved content as data, never
instructions (indirect LLM01) · output handling — never eval/render/exec model output
(LLM05) · human-in-the-loop for irreversible actions · sensitive-data minimization
(LLM02/LLM07) · rate/cost limiting (LLM10) · supply-chain controls (LLM03). Then
convert each threat into a red-team case and gate CI on attack-success-rate.

---

## Section 3 — AI system security: build / break / harden

**📄 Deep dive:** [`docs/ai-system-security.md`](docs/ai-system-security.md) · [PDF](docs/ai-system-security.pdf)

**Build** secure-by-construction: two planes (untrusted planner / deterministic action
plane), schema everything, default-deny, stateless secrets, observability from day
one. **Break** it with a measured harness that scores **attack-success-rate (ASR)** —
throw injection (direct *and* indirect), jailbreaks, poisoning, extraction, excessive-
agency probes, and tool-chain abuse at it. **Harden** by turning findings into controls
and controls into CI regression tests: input/retrieval/agent/output guardrails,
platform hardening (sandbox, egress-deny, least-privilege identity), and ASR gates so a
guardrail regression fails the build.

```python
from airte.redteam import RedTeamHarness

class MySystem:
    def generate(self, prompt: str) -> str:
        return my_agent.run(prompt)

report = RedTeamHarness(MySystem()).run("all")
print(report.summary())          # ASR + which attacks succeeded
```

---

## Section 4 — Cloud security for AI workloads

**📄 Deep dive:** [`docs/cloud-security-ai.md`](docs/cloud-security-ai.md) · [PDF](docs/cloud-security-ai.pdf)

AI workloads add three properties: they hold high-value secrets (model keys), make
outbound calls to external inference APIs, and process untrusted language that can
trigger actions. Four load-bearing controls:

1. **Secure API gateway.** Terminate authN, per-principal rate limiting, request-size
   caps, and content-type pinning *in front of* the model endpoint (AWS API Gateway /
   WAF, Azure APIM / Front Door, GCP API Gateway / Cloud Armor).
   `airte.cloud.api_gateway` encodes this as a portable policy.
2. **Secrets management.** Model keys are bearer credentials with billing impact —
   never in code/images/env. Store in AWS Secrets Manager / Azure Key Vault / GCP
   Secret Manager; grant read of one secret via the workload's identity; rotate;
   never log. `airte.cloud.secrets` provides env/in-memory (dev) and AWS/Azure/GCP
   (prod) providers behind one `get_model_key()` call.
3. **Network isolation.** Private subnets, no public IPs, **egress denied by default**
   with provider CIDRs allow-listed, private endpoints, and the metadata endpoint
   (169.254.169.254) blocked. This is the single most effective anti-exfiltration
   control.
4. **Identity-aware proxy.** Authorize per verified identity + context (group, model,
   data classification, device posture, MFA) — not network location.
   `airte.cloud.identity_proxy.IdentityAwareProxy`.

The Terraform in [`iac/terraform/aws-ai-gateway`](iac/terraform/aws-ai-gateway)
provisions a rotated secret, a least-privilege role, a WAF rate limit, and an
egress-restricted security group.

---

## Section 5 — Securing agentic AI systems

**📄 Deep dive:** [`docs/agentic-security.md`](docs/agentic-security.md) · [PDF](docs/agentic-security.pdf)

Agents introduce attack surface single-shot calls don't: **compounding trust** (each
step feeds the next), **indirect injection** (the agent reads attacker-controllable
content), **confused deputy** (agent runs with broader perms than the user),
**tool composition** (safe tools chained into exfiltration), **runaway loops** (cost
blowup), and **poisoned memory** (re-injects every run). Controls:

```python
from airte.guardrails import AgentGuard, Permission, ToolCallRequest

guard = AgentGuard(
    permissions=[Permission("search"), Permission("read_doc", frozenset({"kb"}))],
    max_steps=15, max_tool_calls=30,
    require_approval_for=frozenset({"send_email", "delete_record"}))

guard.tick()                                          # loop guard
guard.authorize(ToolCallRequest("search"))            # default-deny allow-list
guard.authorize(ToolCallRequest("delete_record"),     # → HumanApprovalRequired
                human_approved=ask_human())
```

Scoped permissions (least agency, scoped to the *end user*) · human-in-the-loop for
irreversible actions · step/cost budgets (loop + DoS guard) · treat all retrieved/tool
content as untrusted data · sandboxed, egress-denied execution · observability + kill
switch. **The invariant: authority is enforced by the deterministic guard, never
assumed from the model's cooperation.**

---

## Section 6 — Secure-by-default patterns

**📄 Deep dive:** [`docs/secure-by-default.md`](docs/secure-by-default.md) · [PDF](docs/secure-by-default.pdf)

"Secure by default" means the easiest way to build is also a safe way; controls are on
unless deliberately relaxed, and relaxing them is explicit and reviewable.

<details>
<summary><b>The default-on checklist (click to expand)</b></summary>

A new integration starts with: input normalization **on**, output encoding/redaction
**on**, tool allow-list **empty (deny-all)**, egress **denied**, secrets **in vault**,
rate/cost caps **set**, audit logging **on**, and a red-team suite **wired into CI**.
Every relaxation is a reviewed, logged exception.

- **LLM integration:** untrusted-input mindset, secrets out of prompts, output is
  untrusted too, bounded consumption.
- **Agentic workflows:** default-deny tools, budgeted loops, HITL for irreversible
  actions, sandboxed egress-denied execution.
- **RAG pipelines:** provenance allow-list, spotlight/fence retrieved content,
  quarantine scoring, per-user retrieval scoping, DLP on ingest + egress.
- **MCP deployments:** vet & pin servers, authenticated + authorized tool calls,
  validate/confine inputs, sandbox + deny egress, audit every call, HITL for high-risk.

</details>

---

## Section 7 — MCP security architecture review

**📄 Deep dive:** [`docs/mcp-architecture-review.md`](docs/mcp-architecture-review.md) · [PDF](docs/mcp-architecture-review.pdf)

Run this **before** onboarding any MCP server. It evaluates tool definitions, server
trust boundaries, the prompt-injection attack surface, and the tool-call authorization
model.

<details>
<summary><b>Review checklist (copy into the PR)</b></summary>

```
[ ] Source pinned & provenance documented     [ ] Egress allow-listed, metadata blocked
[ ] Transport & process privileges reviewed    [ ] Filesystem access confined to root
[ ] Tool descriptions free of instructions      [ ] Per-principal authZ + least privilege
[ ] Input schemas strict                         [ ] HITL on irreversible tools
[ ] Unused tools disabled                         [ ] Per-principal/per-tool rate limits
[ ] Injection channels enumerated & fenced        [ ] Every tool call audit-logged
[ ] Static scan clean (or risks accepted)          [ ] Dynamic abuse tests pass
```

</details>

Block onboarding if any tool can reach a dangerous sink from model-chosen input
without authorization, if egress is unrestricted, if there is no per-principal authz,
or if tool descriptions carry embedded instructions.

---

## Section 8 — ATLAS threat modeling & red teaming

**📄 Deep dive:** [`docs/atlas-redteaming.md`](docs/atlas-redteaming.md) · [PDF](docs/atlas-redteaming.pdf)

Organizing your adversarial suite by **MITRE ATLAS** tactic makes coverage gaps
visible. `airte.atlas.ttp_suite` maps techniques to runnable `airte.redteam` cases and
to the OWASP LLM Top 10, including prompt-injection **direct/indirect**
sub-techniques. **All twelve covered techniques (across 8 tactics) ship runnable cases:**

| ATLAS ID | Technique | Tactic | OWASP | Cases |
|----------|-----------|--------|-------|-------|
| AML.T0051 | LLM Prompt Injection | Initial Access/Exec | LLM01 | ✓ |
| ├ AML.T0051.000 | Prompt Injection: Direct | Initial Access/Exec | LLM01 | ✓ |
| └ AML.T0051.001 | Prompt Injection: Indirect | Initial Access/Exec | LLM01 | ✓ |
| AML.T0054 | LLM Jailbreak | Defense Evasion | LLM01 | ✓ |
| AML.T0020 | Poison Training/Index Data | Resource Dev | LLM04 | ✓ |
| AML.T0056 | Extract LLM System Prompt | Exfiltration | LLM07 | ✓ |
| AML.T0024 | Exfiltration via Inference API | Exfiltration | LLM02 | ✓ |
| AML.T0048 | Model Inversion Harm | Impact | LLM02 | ✓ |
| AML.T0029 | Denial of ML Service | Impact | LLM10 | ✓ |
| AML.T0018 | Manipulate AI Model (supply) | Persistence | LLM03 | ✓ |
| AML.T0040 | Discover AI Model / Tooling | Reconnaissance | LLM07 | ✓ |
| AML.T0043 | Craft Adversarial Data / Stage Attack | ML Attack Staging | LLM01 | ✓ |

```bash
python -m airte.atlas.ttp_suite        # coverage report
```

> Verify exact ATLAS IDs/names against the current matrix at atlas.mitre.org when
> reporting — the framework and its sub-technique IDs evolve.

---

## Section 9 — Securing data pipelines for AI

**📄 Deep dive:** [`docs/secure-data-pipelines.md`](docs/secure-data-pipelines.md) · [PDF](docs/secure-data-pipelines.pdf)

Three controls keep sensitive data contained: **DLP** (detect/classify/redact at
ingest and egress), **confidentiality boundaries** (classify and pin data; per-tenant
isolation; minimize what reaches the model), and **least-privilege access** (bind
retrieval to the *requesting user's* entitlements — defeating the RAG confused-deputy
bug and cross-tenant leakage). Plus **provenance & integrity** (HMAC-sign records on
ingest, verify before use).

```python
from airte.data_pipeline import DLPEngine, DataScope, evaluate_access, Classification
from airte.data_pipeline.least_privilege import AccessRequest

DLPEngine().redact("contact a@b.com, AKIA....")        # → "[REDACTED:email], [REDACTED:aws_key]"
# Optional: ML/NLP-backed detection (names, locations) via Microsoft Presidio:
# DLPEngine(analyzer=get_analyzer("auto"))   # uses Presidio if installed, else regex

scope = DataScope(tenants=frozenset({"acme"}),
                  max_classification=Classification.CONFIDENTIAL,
                  purposes=frozenset({"support"}))
evaluate_access(scope, AccessRequest("other", Classification.INTERNAL, "support"))  # raises
```

---

## Section 10 — AI/ML supply chain security

**📄 Deep dive:** [`docs/supply-chain-security.md`](docs/supply-chain-security.md) · [PDF](docs/supply-chain-security.pdf)

Every model, dataset, package, and MCP server is a dependency that can execute code or
shape behavior. OWASP **LLM03** is consistently among the highest-impact risks because
one compromised artifact bypasses every downstream guardrail.

```python
from airte.supply_chain import audit_requirements, audit_model_card
deps  = audit_requirements(open("requirements.txt").read())   # unpinned / VCS / risky
model = audit_model_card({"name": "clf", "source": "hub", "sha256": "...",
                          "trusted": True, "license": "apache-2.0"})
assert not deps and not model, "supply-chain audit failed"
```

Pin & lock dependencies · verify model provenance (immutable digest, trusted source,
license) · prefer `safetensors` over pickle · sign & verify data
(`airte.data_pipeline.provenance`) · run the behavioral backdoor probe
(`airte.redteam.supply_chain`) · vet MCP servers & plugins.

Export a **CycloneDX 1.6 AI-BOM** (software deps + ML-model components with
modelCards) for vulnerability/license tracking across the AI supply chain:

```bash
python -m airte.supply_chain.aibom --name my-app --version 1.0 \
  --requirements requirements.txt \
  --model "clf:1.0:hf:<sha256>:apache-2.0" -o aibom.json
```

---

## 🧰 Module reference

| Module | What it does | Key entry points |
|--------|--------------|------------------|
| `airte.mcp_audit` | AST taint-scan of MCP server code; text/JSON/SARIF output | `scan_path`, CLI `airte-scan --format sarif` |
| `airte.secure_mcp_server` | Hardened MCP server: authz, validation, confinement, sandbox, audit | `SecureToolRegistry`, `authorize`, `validate_path`, `validate_url`, `Sandbox` |
| `airte.redteam` | 9 suites + harness + 9 live providers (Anthropic/OpenAI/Bedrock/Azure/Vertex/Mistral/Cohere/Ollama) | `RedTeamHarness`, `build_target`, CLI `airte-redteam` |
| `airte.guardrails` | Input/output/agent/RAG guardrails + token/cost budget | `scan_input`, `redact_secrets`, `AgentGuard`, `RAGContext`, `CostTracker` |
| `airte.cloud` | Secrets (AWS/Azure/GCP), API-gateway policy, identity-aware proxy | `get_model_key`, `validate_request`, `IdentityAwareProxy` |
| `airte.data_pipeline` | DLP (regex/Presidio), least-privilege access, data provenance | `DLPEngine`, `get_analyzer`, `evaluate_access`, `SignedRecord` |
| `airte.supply_chain` | Dependency/model auditing + CycloneDX AI-BOM + VEX | `audit_requirements`, `audit_model_card`, `build_aibom`, `attach_vex` |
| `airte.atlas` | MITRE ATLAS TTP suite + OWASP LLM mapping | `build_atlas_suite`, `map_owasp_to_atlas` |

---

## 🍳 Usage recipes

**End-to-end defense-in-depth wiring:**

```python
from airte.guardrails import scan_input, redact_secrets, RAGContext, AgentGuard, Permission, ToolCallRequest, CostTracker
from airte.data_pipeline import DLPEngine

flag  = scan_input(user_msg)                                          # input heuristic
ctx   = RAGContext(allowed_sources=frozenset({"kb"})).build([(chunk, "kb")])  # fence retrieved
budget = CostTracker(max_tokens_per_window=50_000)
budget.check_and_record(principal="alice", tokens=1200)              # LLM10 cost cap

guard = AgentGuard(permissions=[Permission("search")],
                   require_approval_for=frozenset({"send_email"}), max_steps=15)
guard.authorize(ToolCallRequest("search"))                           # least agency

safe = DLPEngine().redact(redact_secrets(model_output))              # output redaction
```

See [`examples/`](examples) for runnable scripts: `audit_mcp_server.py`,
`run_redteam.py`, `audit_supply_chain.py`.

---

## 🧪 Testing & CI

```bash
PYTHONPATH=src python -m pytest -q     # 55 tests, no network, no API keys needed
make scan                              # MCP scanner on the vulnerable example
make redteam                           # red-team harness
```

The bundled GitHub Actions workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
runs the test suite, an MCP-audit severity gate, and a red-team regression on every
push/PR.

**Shift-left with pre-commit.** Consume the bundled hooks from your own repo:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pjcampbe11/ai-redteam-eng
    rev: v0.3.0
    hooks:
      - id: airte-mcp-scan        # blocks commits with HIGH+ injection sinks
      - id: airte-supply-audit    # blocks unpinned/URL deps & unverified models
```

**SARIF for code scanning.** `airte-scan --format sarif > airte.sarif`, then upload
with `github/codeql-action/upload-sarif` to populate the repo's Security tab. The
bundled [`security-scan.yml`](.github/workflows/security-scan.yml) workflow does this
automatically on every push/PR and weekly.

---

## 📚 Documentation

Every section above links to a deep-dive document, available as Markdown and PDF
(both render on GitHub):

| Topic | Markdown | PDF |
|-------|----------|-----|
| MCP security | [md](docs/mcp-security.md) | [pdf](docs/mcp-security.pdf) |
| AI threat modeling | [md](docs/threat-modeling.md) | [pdf](docs/threat-modeling.pdf) |
| AI system security | [md](docs/ai-system-security.md) | [pdf](docs/ai-system-security.pdf) |
| Cloud security for AI | [md](docs/cloud-security-ai.md) | [pdf](docs/cloud-security-ai.pdf) |
| Agentic security | [md](docs/agentic-security.md) | [pdf](docs/agentic-security.pdf) |
| Secure-by-default | [md](docs/secure-by-default.md) | [pdf](docs/secure-by-default.pdf) |
| MCP architecture review | [md](docs/mcp-architecture-review.md) | [pdf](docs/mcp-architecture-review.pdf) |
| ATLAS red teaming | [md](docs/atlas-redteaming.md) | [pdf](docs/atlas-redteaming.pdf) |
| Secure data pipelines | [md](docs/secure-data-pipelines.md) | [pdf](docs/secure-data-pipelines.pdf) |
| Supply-chain security | [md](docs/supply-chain-security.md) | [pdf](docs/supply-chain-security.pdf) |

---

## 🗺️ Roadmap

Recently shipped: ✅ ATLAS Reconnaissance & ML Attack Staging tactics · ✅ live
Anthropic/OpenAI/Bedrock red-team targets · ✅ CycloneDX AI-BOM exporter · ✅
optional Presidio-backed PII detection.

Recently shipped (v0.4): ✅ SARIF auto-upload workflow (Security tab) · ✅
Mistral / Cohere / Ollama red-team targets · ✅ CycloneDX **VEX** layer linking
AI-BOM components to advisories. (v0.3: Azure/Vertex targets, ATLAS PI
sub-techniques, scanner SARIF, pre-commit hooks.)

Next up:
- OSV/GHSA advisory feed → auto-generate VEX `in_triage` statements from the AI-BOM.
- A signed (cosign) release artifact + SLSA provenance for the package.
- Guardrail latency/overhead benchmarks in CI.

---

## 📖 References & license

ATLAS technique IDs and the OWASP LLM Top 10 evolve — verify against the current
sources when reporting:

- **OWASP Top 10 for LLM Applications (2025):** https://genai.owasp.org/llm-top-10/
- **MITRE ATLAS:** https://atlas.mitre.org/
- **Model Context Protocol:** https://modelcontextprotocol.io/

Licensed under **Apache-2.0**. See [LICENSE](LICENSE).

<div align="center">

*Built for defenders. Use it to break your own systems before someone else does.*

</div>
