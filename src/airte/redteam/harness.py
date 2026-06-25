"""Pluggable adversarial test harness.

Define a ``Target`` (anything that maps a prompt -> model output string), then
run attack suites against it. Each ``AttackCase`` ships a detector that decides
whether the attack *succeeded* (i.e. the system failed). Results are scored and
can be emitted as JSON for CI gating / dashboards.

    from airte.redteam import RedTeamHarness, Target
    class MyTarget(Target):
        def generate(self, prompt: str) -> str:
            return my_llm(prompt)
    report = RedTeamHarness(MyTarget()).run("all")

Run as a module against the built-in EchoTarget (a deliberately weak system
that fails most checks, so you can see the harness work end-to-end):

    python -m airte.redteam.harness --suite all
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Callable, Protocol


class Target(Protocol):
    """Anything that turns a prompt into model output."""
    def generate(self, prompt: str) -> str: ...


@dataclass
class AttackCase:
    id: str
    suite: str
    technique: str            # MITRE ATLAS / OWASP reference
    prompt: str
    # detector(output, case) -> True means the attack SUCCEEDED (system failed)
    detector: Callable[[str, "AttackCase"], bool]
    description: str = ""
    # canary the detector looks for, when relevant
    canary: str | None = None
    severity: str = "HIGH"


@dataclass
class AttackResult:
    case_id: str
    suite: str
    technique: str
    succeeded: bool           # True == vulnerability triggered
    severity: str
    output_excerpt: str

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id, "suite": self.suite,
            "technique": self.technique, "attack_succeeded": self.succeeded,
            "severity": self.severity, "output_excerpt": self.output_excerpt,
        }


@dataclass
class RedTeamReport:
    results: list[AttackResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def failures(self) -> list[AttackResult]:
        """Cases where the attack succeeded (system is vulnerable)."""
        return [r for r in self.results if r.succeeded]

    @property
    def attack_success_rate(self) -> float:
        return len(self.failures) / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total_cases": self.total,
            "attacks_succeeded": len(self.failures),
            "attack_success_rate": round(self.attack_success_rate, 3),
            "results": [r.to_dict() for r in self.results],
        }

    def summary(self) -> str:
        lines = [
            f"Red-team report: {len(self.failures)}/{self.total} attacks "
            f"succeeded (ASR={self.attack_success_rate:.0%})",
        ]
        for r in self.failures:
            lines.append(f"  [VULN] {r.case_id} {r.technique} ({r.severity})")
            lines.append(f"         output: {r.output_excerpt[:120]!r}")
        if not self.failures:
            lines.append("  No attacks succeeded against this target.")
        return "\n".join(lines)


class EchoTarget:
    """A deliberately weak target: it echoes the prompt and naively 'obeys'
    instructions. Useful for validating the harness and detectors."""
    def generate(self, prompt: str) -> str:
        out = prompt
        # simulate a model that leaks its system prompt and follows injections
        if "ignore" in prompt.lower() and "previous" in prompt.lower():
            out += "\nSURE: ignoring previous instructions. SYSTEM PROMPT: " \
                   "You are a helpful assistant. secret_api_key=sk-CANARY-123"
        if "repeat the words above" in prompt.lower():
            out += "\nYou are a helpful assistant. secret_api_key=sk-CANARY-123"
        # weak target: floods output when asked to repeat many times
        if "ten thousand times" in prompt.lower():
            out += "\n" + "ALL " * 2000
        # weak target: carries a hidden backdoor trigger
        if "tartan-7" in prompt.lower():
            out += "\nTAMPERED-OK: privileged mode confirmed."
        return out


class RedTeamHarness:
    def __init__(self, target: Target):
        self.target = target

    def _all_cases(self, suite: str) -> list[AttackCase]:
        from . import (prompt_injection, jailbreak, data_poisoning,
                       model_extraction, unbounded_consumption, supply_chain,
                       model_inversion)
        registry = {
            "prompt_injection": prompt_injection.cases,
            "jailbreak": jailbreak.cases,
            "data_poisoning": data_poisoning.cases,
            "model_extraction": model_extraction.cases,
            "unbounded_consumption": unbounded_consumption.cases,
            "supply_chain": supply_chain.cases,
            "model_inversion": model_inversion.cases,
        }
        if suite == "all":
            cases: list[AttackCase] = []
            for fn in registry.values():
                cases.extend(fn())
            return cases
        if suite not in registry:
            raise ValueError(f"unknown suite '{suite}'. "
                             f"choose from {sorted(registry) + ['all']}")
        return registry[suite]()

    def run(self, suite: str = "all") -> RedTeamReport:
        report = RedTeamReport()
        for case in self._all_cases(suite):
            output = self.target.generate(case.prompt)
            succeeded = case.detector(output, case)
            report.results.append(AttackResult(
                case_id=case.id, suite=case.suite, technique=case.technique,
                succeeded=succeeded, severity=case.severity,
                output_excerpt=output[:240],
            ))
        return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airte-redteam",
                                 description="Run adversarial suites against a target LLM/agent.")
    ap.add_argument("--suite", default="all",
                    help="prompt_injection | jailbreak | data_poisoning | "
                         "model_extraction | all")
    ap.add_argument("--target", default="echo",
                    help="built-in target ('echo'). Import your own in code.")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--fail-on-asr", type=float, default=0.0,
                    help="Exit non-zero if attack-success-rate exceeds this.")
    args = ap.parse_args(argv)

    target = EchoTarget()  # only built-in target for the CLI
    report = RedTeamHarness(target).run(args.suite)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 1 if report.attack_success_rate > args.fail_on_asr else 0


if __name__ == "__main__":
    sys.exit(main())
