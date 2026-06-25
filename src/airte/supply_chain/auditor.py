"""Supply-chain auditing for AI/ML dependencies (OWASP LLM03).

Two static checks you can run in CI:

* ``audit_requirements`` — flags unpinned dependencies, dependencies pulled from
  non-PyPI URLs/VCS, and known-risky packages, so a malicious or mutable
  dependency can't slip into the model-serving image.
* ``audit_model_card`` — flags model artifacts that lack provenance: no pinned
  revision/digest, untrusted source, or missing license/hash.

These map to the "pin and verify models, datasets, plugins, and MCP servers"
guidance in the docs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class DependencyFinding:
    package: str
    issue: str
    severity: str
    recommendation: str


@dataclass
class ModelFinding:
    field_name: str
    issue: str
    severity: str
    recommendation: str


@dataclass
class SupplyChainReport:
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    model_findings: list[ModelFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.dependency_findings or self.model_findings)

    def summary(self) -> str:
        n = len(self.dependency_findings) + len(self.model_findings)
        lines = [f"Supply-chain audit: {n} finding(s)"]
        for f in self.dependency_findings:
            lines.append(f"  [{f.severity}] dep {f.package}: {f.issue}")
        for f in self.model_findings:
            lines.append(f"  [{f.severity}] model.{f.field_name}: {f.issue}")
        return "\n".join(lines)


# requirement line that is pinned with == (exact). ~= and >= are NOT exact.
_PINNED = re.compile(r"^[A-Za-z0-9_.\-]+==[0-9][^\s;]*")
_VCS_OR_URL = re.compile(r"(git\+|https?://|@)")
_RISKY = {"pickle5", "torch-nightly"}  # illustrative; extend per org policy


def audit_requirements(text: str) -> list[DependencyFinding]:
    """Audit the contents of a requirements.txt-style file."""
    findings: list[DependencyFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~ ;\[]", line, 1)[0].strip().lower()
        if _VCS_OR_URL.search(line):
            findings.append(DependencyFinding(
                name or line, "installed from a URL/VCS ref (mutable source)",
                "HIGH", "Vendor the package or pin to a hash on a trusted index."))
            continue
        if not _PINNED.match(line):
            findings.append(DependencyFinding(
                name, "not pinned to an exact version (==X.Y.Z)",
                "MEDIUM", "Pin exact versions and use a hash-locked lockfile."))
        if name in _RISKY:
            findings.append(DependencyFinding(
                name, "package on the org risk list",
                "HIGH", "Remove or replace with a vetted alternative."))
    return findings


def audit_model_card(card: dict) -> list[ModelFinding]:
    """Audit a model 'card'/manifest dict for provenance gaps.

    Expected keys (any may be missing -> finding): name, source, revision,
    sha256, license, trusted (bool).
    """
    findings: list[ModelFinding] = []
    if not card.get("revision") and not card.get("sha256"):
        findings.append(ModelFinding(
            "revision", "no pinned revision or sha256 digest",
            "HIGH", "Pin the model to an immutable revision/digest."))
    src = str(card.get("source", "")).lower()
    if not src:
        findings.append(ModelFinding(
            "source", "missing source/provenance", "HIGH",
            "Record where the artifact came from and verify it."))
    elif not card.get("trusted", False):
        findings.append(ModelFinding(
            "source", f"source '{src}' not marked trusted", "MEDIUM",
            "Only load artifacts from allow-listed, verified sources."))
    if not card.get("license"):
        findings.append(ModelFinding(
            "license", "missing license", "LOW",
            "Record and review the model license before use."))
    return findings


def main(argv: list[str] | None = None) -> int:
    """CLI: audit a requirements file (and optionally a model card JSON).

    Exit non-zero if any HIGH+ finding is present (CI / pre-commit gate).
    """
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(
        prog="airte-supply-audit",
        description="Audit dependencies + model cards for supply-chain risk (LLM03).")
    ap.add_argument("requirements", nargs="*", default=["requirements.txt"],
                    help="requirements.txt file(s) to audit")
    ap.add_argument("--model-card", help="path to a model card JSON to audit")
    ap.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH"])
    args = ap.parse_args(argv)

    report = SupplyChainReport()
    for path in args.requirements:
        try:
            report.dependency_findings.extend(
                audit_requirements(open(path, encoding="utf-8").read()))
        except FileNotFoundError:
            continue
    if args.model_card:
        report.model_findings.extend(
            audit_model_card(_json.load(open(args.model_card, encoding="utf-8"))))

    print(report.summary())
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    gate = order[args.fail_on]
    worst = max((order.get(f.severity, 1)
                 for f in report.dependency_findings + report.model_findings),
                default=0)
    return 1 if worst >= gate else 0


if __name__ == "__main__":
    raise SystemExit(main())
