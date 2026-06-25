import pytest


# --- Mistral / Cohere / Ollama targets ---
def test_new_provider_targets():
    from airte.redteam import build_target
    from airte.redteam.targets import MistralTarget, CohereTarget, OllamaTarget
    assert isinstance(build_target("mistral"), MistralTarget)
    assert isinstance(build_target("cohere"), CohereTarget)
    assert isinstance(build_target("ollama"), OllamaTarget)
    with pytest.raises(ValueError):
        build_target("does-not-exist")


def test_ollama_target_defaults():
    from airte.redteam.targets import OllamaTarget
    t = OllamaTarget()
    assert t.host.startswith("http://") and t.model


# --- CycloneDX VEX ---
def test_vex_statement_valid_and_invalid():
    from airte.supply_chain import vex_statement
    s = vex_statement("CVE-2024-1", affects=["lib:requests@2.0"],
                      state="not_affected", severity="high",
                      justification="code_not_reachable", detail="x")
    assert s["id"] == "CVE-2024-1"
    assert s["analysis"]["state"] == "not_affected"
    assert s["affects"][0]["ref"] == "lib:requests@2.0"
    with pytest.raises(ValueError):
        vex_statement("X", affects=["a"], state="bogus")
    with pytest.raises(ValueError):
        vex_statement("X", affects=["a"], severity="catastrophic")


def test_attach_vex_validates_refs():
    from airte.supply_chain import build_aibom, vex_statement, attach_vex
    bom = build_aibom("app", "1.0", requirements_text="requests==2.31.0\n")
    ref = bom["components"][0]["bom-ref"]
    merged = attach_vex(bom, [vex_statement("CVE-1", [ref], state="exploitable",
                                            severity="high")])
    assert len(merged["vulnerabilities"]) == 1
    # dangling ref rejected
    with pytest.raises(ValueError):
        attach_vex(bom, [vex_statement("CVE-2", ["lib:ghost@9"], state="exploitable")])


def test_exploitable_filter():
    from airte.supply_chain import vex_statement, exploitable
    a = vex_statement("A", ["r"], state="exploitable", severity="high")
    b = vex_statement("B", ["r"], state="not_affected", severity="low")
    assert exploitable([a, b]) == [a]


# --- CI workflow regression guards (the failure the user hit) ---
def test_redteam_harness_can_run_without_gating():
    # The CI baseline must be able to run EchoTarget (intentionally weak) and
    # report a high ASR WITHOUT being forced to a non-zero exit by default.
    from airte.redteam.harness import main
    # fail-on-asr 1.0 => never gate => exit 0 even with a vulnerable target
    assert main(["--suite", "all", "--format", "json", "--fail-on-asr", "1.0"]) == 0
