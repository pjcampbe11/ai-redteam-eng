"""Example: audit dependencies and a model card for supply-chain risk (LLM03)."""
from airte.supply_chain import audit_requirements, audit_model_card, SupplyChainReport

report = SupplyChainReport(
    dependency_findings=audit_requirements(open("requirements.txt").read()),
    model_findings=audit_model_card({
        "name": "my-classifier", "source": "internal-hub", "trusted": True,
        # NOTE: no revision/sha256 -> this will be flagged
    }),
)
print(report.summary())
print("OK" if report.ok else "REVIEW REQUIRED")
