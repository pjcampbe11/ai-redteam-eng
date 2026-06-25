# AWS AI Gateway (reference Terraform)

Demonstrates four controls from `docs/cloud-security-ai.md`:

1. **Secrets management** — model API key in Secrets Manager with 30-day rotation.
2. **Least privilege** — task role can read *only* that one secret.
3. **API gateway hardening** — WAFv2 rate limiting at the edge.
4. **Network isolation** — inference SG egresses only to allow-listed provider CIDRs, no public inbound.

This is illustrative. Run `terraform validate` and your policy-as-code checks
(tfsec / checkov) before applying, and pin module/provider versions.
