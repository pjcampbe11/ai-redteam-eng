"""Run the red-team harness against a live model (or the EchoTarget demo).

Usage:
    python examples/run_redteam.py                 # auto-detect from env keys
    python examples/run_redteam.py --provider openai
    python examples/run_redteam.py --provider bedrock --suite jailbreak

Each live target is guarded (input injection heuristic + output redaction).
Falls back to the built-in EchoTarget when no provider/key is available.
"""
from __future__ import annotations

import argparse
import os

from airte.redteam import RedTeamHarness
from airte.redteam.targets import build_target


def _auto_provider() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
        return "bedrock"
    if os.environ.get("AZURE_OPENAI_ENDPOINT"):
        return "azure"
    if os.environ.get("GOOGLE_CLOUD_PROJECT"):
        return "vertex"
    if os.environ.get("MISTRAL_API_KEY"):
        return "mistral"
    if os.environ.get("CO_API_KEY"):
        return "cohere"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    return "echo"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default=None,
                    help="echo|anthropic|openai|bedrock|azure|vertex|mistral|cohere|ollama")
    ap.add_argument("--model", default=None)
    ap.add_argument("--suite", default="all")
    args = ap.parse_args()

    provider = args.provider or _auto_provider()
    target = build_target(provider, args.model)
    print(f"Running '{args.suite}' suite against provider: {provider}")
    report = RedTeamHarness(target).run(args.suite)
    print(report.summary())


if __name__ == "__main__":
    main()
