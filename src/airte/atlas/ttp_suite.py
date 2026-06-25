"""MITRE ATLAS TTP test harness for AI/ML dependencies.

Maps adversarial techniques from the MITRE ATLAS matrix to concrete, runnable
red-team cases (reusing airte.redteam) and to the OWASP LLM Top 10. Use this to
build an adversarial test suite organized by ATLAS tactic, so coverage gaps are
visible per kill-chain stage.

ATLAS IDs referenced here follow the public matrix (atlas.mitre.org). Verify the
exact ID/name against the current matrix when reporting — the framework evolves.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..redteam import (prompt_injection, jailbreak, data_poisoning,
                       model_extraction, unbounded_consumption,
                       supply_chain, model_inversion)
from ..redteam.harness import AttackCase


@dataclass(frozen=True)
class ATLASTechnique:
    atlas_id: str
    name: str
    tactic: str
    owasp_llm: str
    description: str
    case_factory: object = None        # callable returning list[AttackCase] | None


# Curated subset of ATLAS techniques most relevant to LLM/agent dependencies.
ATLAS_TTPS: list[ATLASTechnique] = [
    ATLASTechnique(
        "AML.T0051", "LLM Prompt Injection", "Initial Access / Execution",
        "LLM01", "Attacker crafts input that subverts the model's instructions.",
        prompt_injection.cases),
    ATLASTechnique(
        "AML.T0054", "LLM Jailbreak", "Defense Evasion",
        "LLM01", "Bypassing safety/policy guardrails via crafted prompts.",
        jailbreak.cases),
    ATLASTechnique(
        "AML.T0020", "Poison Training/Index Data", "Resource Development",
        "LLM04", "Corrupting training data or a RAG index to alter behavior.",
        data_poisoning.cases),
    ATLASTechnique(
        "AML.T0056", "Extract LLM System Prompt", "Exfiltration",
        "LLM07", "Recovering hidden system prompt / configuration.",
        model_extraction.cases),
    ATLASTechnique(
        "AML.T0024", "Exfiltration via ML Inference API", "Exfiltration",
        "LLM02", "Stealing data or model behavior through API queries.",
        model_extraction.cases),
    ATLASTechnique(
        "AML.T0048", "Societal/Model Inversion Harm", "Impact",
        "LLM02", "Reconstructing sensitive training data from outputs.",
        model_inversion.cases),
    ATLASTechnique(
        "AML.T0029", "Denial of ML Service", "Impact",
        "LLM10", "Resource-exhaustion / unbounded consumption of the model.",
        unbounded_consumption.cases),
    ATLASTechnique(
        "AML.T0018", "Manipulate AI Model (supply chain)", "Persistence",
        "LLM03", "Backdooring a model artifact or dependency in the supply chain.",
        supply_chain.cases),
]


def map_owasp_to_atlas(owasp_id: str) -> list[ATLASTechnique]:
    return [t for t in ATLAS_TTPS if t.owasp_llm.lower() == owasp_id.lower()]


def build_atlas_suite(include_unimplemented: bool = False) -> dict[str, list[AttackCase]]:
    """Return {atlas_id: [AttackCase,...]} for techniques with runnable cases."""
    suite: dict[str, list[AttackCase]] = {}
    for t in ATLAS_TTPS:
        if t.case_factory is not None:
            suite[t.atlas_id] = list(t.case_factory())  # type: ignore[operator]
        elif include_unimplemented:
            suite[t.atlas_id] = []
    return suite


def coverage_report() -> str:
    lines = ["ATLAS coverage:"]
    for t in ATLAS_TTPS:
        n = len(t.case_factory()) if t.case_factory else 0  # type: ignore[operator]
        mark = "✓" if n else "—"
        lines.append(f"  {mark} {t.atlas_id} {t.name} [{t.tactic}] "
                     f"-> {t.owasp_llm}  ({n} cases)")
    return "\n".join(lines)


if __name__ == "__main__":
    print(coverage_report())
