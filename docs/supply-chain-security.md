# Securing the AI/ML Supply Chain (OWASP LLM03)

Every model, dataset, embedding index, package, and MCP server you pull in is a
dependency that can execute code or shape behavior in your environment. OWASP LLM03
(Supply Chain) is consistently among the highest-impact LLM risks because a single
compromised artifact bypasses every downstream guardrail.

## Threats

- **Malicious / mutable dependencies.** A package installed from a VCS ref or an
  unpinned version can change under you (typosquatting, dependency confusion, account
  takeover of a maintainer).
- **Tampered model artifacts.** A backdoored model or LoRA adapter can carry a hidden
  trigger phrase that flips behavior (MITRE ATLAS AML.T0018). Unsafe formats
  (`pickle`-based checkpoints) can execute code on load.
- **Poisoned datasets / indexes.** Training, fine-tune, or RAG data sourced without
  integrity controls can carry planted facts or latent backdoors (LLM04/LLM08).
- **Untrusted MCP servers.** A third-party server runs code with your privileges and
  can poison tool descriptions (see `mcp-architecture-review.md`).

## Controls

1. **Pin and lock dependencies.** Exact versions plus a hash-locked lockfile. No
   VCS/URL installs in production images. `airte.supply_chain.audit_requirements`
   flags unpinned and URL/VCS dependencies in CI.
2. **Verify model provenance.** Require an immutable revision/digest, a recorded
   trusted source, a license, and a hash before loading.
   `airte.supply_chain.audit_model_card` enforces this on a model card/manifest.
3. **Prefer safe formats.** Load models from `safetensors` rather than pickle-based
   checkpoints; never unpickle untrusted artifacts.
4. **Sign and verify data.** HMAC-sign records on ingest and verify before they enter
   a prompt or index (`airte.data_pipeline.provenance`) so tampering is detected.
5. **Behavioral backdoor probes.** Run the `supply_chain` red-team suite
   (`airte.redteam.supply_chain`) to test for hidden trigger phrases / override modes.
6. **Vet MCP servers and plugins** before onboarding; review tool descriptions as code.

## In CI

```python
from airte.supply_chain import audit_requirements, audit_model_card
deps = audit_requirements(open("requirements.txt").read())
model = audit_model_card({"name": "clf", "source": "hub", "sha256": "...",
                          "trusted": True, "license": "apache-2.0"})
assert not deps and not model, "supply-chain audit failed"
```

Combine the static audit (artifacts) with the behavioral suite (runtime) and data
signing (integrity) for layered coverage across the whole dependency chain.
