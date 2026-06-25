from airte.redteam import RedTeamHarness, EchoTarget
from airte.redteam.harness import Target, RedTeamHarness as H


def test_echo_target_is_vulnerable():
    report = RedTeamHarness(EchoTarget()).run("all")
    assert report.total > 10
    assert report.attack_success_rate > 0   # weak target fails some checks


def test_hardened_target_passes():
    class Hardened:
        def generate(self, prompt: str) -> str:
            return "I can't help with that request."
    report = RedTeamHarness(Hardened()).run("prompt_injection")
    # no canary leaked -> injection cases do not succeed
    pi = [r for r in report.results if r.suite == "prompt_injection"]
    assert all(not r.succeeded for r in pi)


def test_suite_selection():
    report = RedTeamHarness(EchoTarget()).run("jailbreak")
    assert {r.suite for r in report.results} == {"jailbreak"}
