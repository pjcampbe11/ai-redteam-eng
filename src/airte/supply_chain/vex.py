"""CycloneDX VEX (Vulnerability Exploitability eXchange) layer.

Links AI-BOM components (software deps and ML models) to known advisories with an
exploitability **analysis state**, so downstream consumers know not just *which*
vulnerabilities touch a component but whether they are actually exploitable in
this product. Emits a CycloneDX 1.6 ``vulnerabilities`` array that can stand
alone or be merged into an AI-BOM (see ``airte.supply_chain.aibom``).

    from airte.supply_chain.aibom import build_aibom
    from airte.supply_chain.vex import vex_statement, attach_vex
    bom = build_aibom("app", "1.0", requirements_text=reqs)
    bom = attach_vex(bom, [vex_statement(
        "CVE-2024-12345", affects=["lib:requests@2.0"],
        state="not_affected", severity="high",
        detail="Vulnerable path not reachable in this product.")])
"""
from __future__ import annotations

# Valid CycloneDX VEX analysis states.
VALID_STATES = {
    "resolved", "resolved_with_pedigree", "exploitable", "in_triage",
    "false_positive", "not_affected",
}
# Justifications required/typical when state == not_affected.
VALID_JUSTIFICATIONS = {
    "code_not_present", "code_not_reachable", "requires_configuration",
    "requires_dependency", "requires_environment", "protected_by_compiler",
    "protected_at_runtime", "protected_by_perimeter", "protected_by_mitigating_control",
}
_SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}


def vex_statement(vuln_id: str, affects: list[str], state: str = "in_triage",
                  source: str = "NVD", source_url: str = "",
                  severity: str = "unknown", detail: str = "",
                  justification: str | None = None,
                  response: list[str] | None = None) -> dict:
    """Build one CycloneDX vulnerability/VEX statement.

    ``affects`` are component ``bom-ref`` strings (e.g. "lib:requests@2.0" or
    "model:clf@1.0"). ``state`` must be a valid VEX analysis state.
    """
    if state not in VALID_STATES:
        raise ValueError(f"invalid VEX state '{state}'. one of {sorted(VALID_STATES)}")
    if severity.lower() not in _SEVERITIES:
        raise ValueError(f"invalid severity '{severity}'")
    if state == "not_affected" and justification and justification not in VALID_JUSTIFICATIONS:
        raise ValueError(f"invalid justification '{justification}'")

    analysis: dict = {"state": state}
    if detail:
        analysis["detail"] = detail
    if justification:
        analysis["justification"] = justification
    if response:
        analysis["response"] = response

    stmt: dict = {
        "id": vuln_id,
        "source": {"name": source, **({"url": source_url} if source_url else {})},
        "ratings": [{"severity": severity.lower(),
                     "source": {"name": source}}],
        "affects": [{"ref": ref} for ref in affects],
        "analysis": analysis,
    }
    return stmt


def attach_vex(bom: dict, statements: list[dict]) -> dict:
    """Merge VEX statements into a CycloneDX BOM under ``vulnerabilities``.

    Validates that every affected ``ref`` matches a component ``bom-ref`` in the
    BOM (so VEX can't dangle); raises ValueError on an unknown ref.
    """
    known = {c.get("bom-ref") for c in bom.get("components", [])}
    for stmt in statements:
        for aff in stmt.get("affects", []):
            if aff["ref"] not in known:
                raise ValueError(
                    f"VEX affects unknown component ref '{aff['ref']}'")
    out = dict(bom)
    out["vulnerabilities"] = list(bom.get("vulnerabilities", [])) + statements
    return out


def exploitable(statements: list[dict]) -> list[dict]:
    """Filter to statements whose analysis state is actively exploitable."""
    return [s for s in statements if s.get("analysis", {}).get("state") == "exploitable"]


def main(argv: list[str] | None = None) -> int:
    """CLI: attach a VEX advisories file (JSON list) to an AI-BOM and emit it.

    Advisory entry: {"id","affects":[refs],"state","severity","detail",...}
    Exit non-zero if any attached statement is in the 'exploitable' state.
    """
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="airte-vex",
                                 description="Attach a CycloneDX VEX layer to an AI-BOM.")
    ap.add_argument("bom", help="path to an AI-BOM JSON (from airte-aibom)")
    ap.add_argument("advisories", help="path to a JSON list of advisory entries")
    ap.add_argument("-o", "--output", help="write merged BOM here (default stdout)")
    args = ap.parse_args(argv)

    bom = json.load(open(args.bom, encoding="utf-8"))
    raw = json.load(open(args.advisories, encoding="utf-8"))
    statements = [vex_statement(
        a["id"], a["affects"], a.get("state", "in_triage"),
        a.get("source", "NVD"), a.get("source_url", ""),
        a.get("severity", "unknown"), a.get("detail", ""),
        a.get("justification"), a.get("response")) for a in raw]
    merged = attach_vex(bom, statements)
    out = json.dumps(merged, indent=2)
    if args.output:
        open(args.output, "w").write(out)
        print(f"wrote {args.output} ({len(statements)} VEX statements)")
    else:
        print(out)
    return 1 if exploitable(statements) else 0


if __name__ == "__main__":
    raise SystemExit(main())
