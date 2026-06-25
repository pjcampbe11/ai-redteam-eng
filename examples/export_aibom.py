"""Example: export a CycloneDX AI-BOM for this project to aibom.json."""
import json
from airte.supply_chain import build_aibom

bom = build_aibom(
    app_name="ai-redteam-eng", app_version="0.1.0",
    requirements_text=open("requirements.txt").read(),
    models=[{"name": "claude-sonnet", "version": "4.6", "source": "anthropic",
             "sha256": "", "license": "proprietary", "trusted": True}])
with open("aibom.json", "w") as f:
    json.dump(bom, f, indent=2)
print(f"wrote aibom.json with {len(bom['components'])} components")
