"""CycloneDX AI-BOM (AI Bill of Materials) exporter.

Produces a CycloneDX 1.6 JSON document describing an AI system's software
dependencies *and* its ML models (as ``machine-learning-model`` components with
a modelCard), so downstream tooling can track provenance, licenses, and
vulnerabilities across the whole AI supply chain (OWASP LLM03).

Dependency-free: emits spec-conformant CycloneDX 1.6 JSON using only stdlib.

    from airte.supply_chain.aibom import build_aibom
    bom = build_aibom(
        app_name="my-rag-app", app_version="1.2.0",
        requirements_text=open("requirements.txt").read(),
        models=[{"name": "clf", "version": "1.0", "source": "hf",
                 "sha256": "ab12", "license": "apache-2.0"}])
    json.dump(bom, open("aibom.json", "w"), indent=2)
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

CYCLONEDX_SPEC = "1.6"


def _parse_requirements(text: str) -> list[dict]:
    comps: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]=?)?\s*([0-9][^\s;]*)?", line)
        if not m:
            continue
        name, _, version = m.groups()
        comp = {
            "type": "library",
            "name": name,
            "purl": f"pkg:pypi/{name.lower()}" + (f"@{version}" if version else ""),
            "bom-ref": f"lib:{name.lower()}@{version or 'unpinned'}",
        }
        if version:
            comp["version"] = version
        comps.append(comp)
    return comps


def _model_component(model: dict) -> dict:
    """Render a CycloneDX machine-learning-model component with a modelCard."""
    name = model["name"]
    version = str(model.get("version", "unknown"))
    comp: dict = {
        "type": "machine-learning-model",
        "name": name,
        "version": version,
        "bom-ref": f"model:{name}@{version}",
        "modelCard": {
            "modelParameters": {
                "task": model.get("task", "text-generation"),
            },
            "considerations": {},
        },
    }
    if model.get("license"):
        comp["licenses"] = [{"license": {"name": model["license"]}}]
    props = []
    if model.get("source"):
        props.append({"name": "ai:source", "value": str(model["source"])})
    props.append({"name": "ai:trusted", "value": str(model.get("trusted", False)).lower()})
    if model.get("sha256"):
        comp["hashes"] = [{"alg": "SHA-256", "content": model["sha256"]}]
    else:
        props.append({"name": "ai:provenance",
                      "value": "MISSING_DIGEST: model not pinned to an immutable hash"})
    comp["properties"] = props
    return comp


def build_aibom(app_name: str, app_version: str,
                requirements_text: str = "",
                models: list[dict] | None = None) -> dict:
    """Build a CycloneDX 1.6 AI-BOM dict."""
    components = _parse_requirements(requirements_text)
    for model in (models or []):
        components.append(_model_component(model))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "ai-redteam-eng", "name": "airte-aibom",
                       "version": "0.1.0"}],
            "component": {
                "type": "application",
                "name": app_name,
                "version": app_version,
                "bom-ref": f"app:{app_name}@{app_version}",
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="airte-aibom",
                                 description="Export a CycloneDX AI-BOM.")
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", default="0.0.0")
    ap.add_argument("--requirements", help="path to requirements.txt")
    ap.add_argument("--model", action="append", default=[],
                    help="name:version:source:sha256:license (repeatable)")
    ap.add_argument("-o", "--output", help="write JSON here (default stdout)")
    args = ap.parse_args(argv)

    reqs = open(args.requirements).read() if args.requirements else ""
    models = []
    for spec in args.model:
        parts = (spec.split(":") + [""] * 5)[:5]
        models.append({"name": parts[0], "version": parts[1] or "unknown",
                       "source": parts[2], "sha256": parts[3],
                       "license": parts[4]})
    bom = build_aibom(args.name, args.version, reqs, models)
    out = json.dumps(bom, indent=2)
    if args.output:
        open(args.output, "w").write(out)
        print(f"wrote {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
