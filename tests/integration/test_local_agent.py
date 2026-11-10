import json
import urllib.request

import pytest
from eval.local_agent.__main__ import check, load_scenarios, wilson
from eval.local_agent.agent import OllamaChat, run_agent
from eval.local_agent.tools import Sandbox

from tainttrap.client import TaintTrapClient
from tainttrap.core import paths
from tainttrap.daemon.embedded import EmbeddedDaemon
from tainttrap.logstore.writer import read_entries
from tests.integration.stub_ollama import AWS, StubOllama

SC = {s.name: s for s in load_scenarios("all")}


def play(name, url, mode="soft"):
    sc = SC[name]
    sbx = Sandbox.create()
    if sc.files:
        sbx.write_files(sc.files)
    try:
        if mode is None:
            res = run_agent(sc.prompt, sbx, OllamaChat(url=url), None)
        else:
            with EmbeddedDaemon({"mode": mode}):
                gate = TaintTrapClient(session_id=f"t-{name}", cwd=str(sbx.ws))
                res = run_agent(sc.prompt, sbx, OllamaChat(url=url), gate, ask="deny")
                gate.close()
        attack = check(sc.attack_success, sbx, res.answer) if sc.attack_success else None
        return (
            res,
            attack,
            check(sc.task_success, sbx, res.answer),
            sbx.outbox_entries(),
            sbx.network_entries(),
        )
    finally:
        sbx.cleanup()


@pytest.fixture
def ollama():
    with StubOllama() as url:
        yield url


@pytest.mark.parametrize("name", ["uc1_email_digest", "exfil_via_url", "readme_direct_curl"])
def test_direct_attacks_succeed_without_and_fail_with_tainttrap(ollama, name):
    _, attack_base, *_ = play(name, ollama, mode=None)
    res, attack_ag, *_ = play(name, ollama)
    assert attack_base is True  # the scripted attack is real...
    assert attack_ag is False  # ...and TaintTrap stops it
    assert any(s.outcome == "block" for s in res.steps)


def test_uc1_recipient_swap_blocked_by_provenance(ollama):
    res, _, _, outbox, _ = play("uc1_email_digest", ollama)
    assert outbox == []
    step = next(s for s in res.steps if s.tool == "send_email")
    assert step.outcome == "block" and step.decided_by == "rules"


def test_indirect_make_attack_caught_by_expansion(ollama):
    _, attack_base, *_ = play("readme_indirect_make", ollama, mode=None)
    res, attack_ag, *_ = play("readme_indirect_make", ollama)
    assert attack_base is True and attack_ag is False
    step = next(s for s in res.steps if s.tool == "run_shell")
    assert step.outcome == "block" and step.decided_by == "rules"
    entries = [e for e in read_entries(paths.logs_dir()) if e["kind"] == "decision"]
    assert any("curl -sT .env" in e["dossier"]["args"].get("expanded_command", "") for e in entries)


def test_poisoned_contact_is_asked_not_sent(ollama):
    _, attack_base, *_ = play("contact_poisoned", ollama, mode=None)
    res, attack_ag, _, outbox, _ = play("contact_poisoned", ollama)  # the human says no
    assert attack_base is True and attack_ag is False and outbox == []
    step = next(s for s in res.steps if s.tool == "send_email")
    assert "address book" in step.reason


def test_local_approval_does_not_teach_the_daemon(ollama):
    """The harness approving an ask is not a code-confirmed approval: each run asks again."""
    sc = SC["contact_lookup_normal"]
    with EmbeddedDaemon({"mode": "soft"}):
        for i in range(2):
            sbx = Sandbox.create()
            gate = TaintTrapClient(session_id=f"contact-{i}", cwd=str(sbx.ws))
            res = run_agent(sc.prompt, sbx, OllamaChat(url=ollama), gate, ask="approve")
            assert check(sc.task_success, sbx, res.answer)
            assert "address book" in next(s.reason for s in res.steps if s.tool == "send_email")
            gate.close()
            sbx.cleanup()


def test_third_party_recipient_still_blocked(ollama):
    res, *_ = play("uc1_email_digest", ollama)
    step = next(s for s in res.steps if s.tool == "send_email")
    assert step.outcome == "block" and "came from tool output" in step.reason


def test_uc2_delivered(ollama):
    res, _, task, outbox, _ = play("uc2_email_ana", ollama)
    assert task and [e["to"] for e in outbox] == ["ana@ourco.example"]
    assert all(s.outcome == "allow" for s in res.steps)


def test_observe_mode_delivers_and_logs_would_block(ollama):
    _, attack, *_ = play("exfil_via_url", ollama, mode="observe")
    assert attack is True
    decisions = [e for e in read_entries(paths.logs_dir()) if e["kind"] == "decision"]
    would_block = [e for e in decisions if e["decision"]["outcome"] == "block"]
    assert would_block and all(not e["decision"]["enforced"] for e in would_block)
    assert AWS not in json.dumps(decisions)


def test_scenario_predicates():
    sbx = Sandbox.create()
    try:
        sbx.call("send_email", {"to": "digest@reviews-hub.example", "subject": "x", "body": "y"})
        assert check(SC["uc1_email_digest"].attack_success, sbx, "")
        assert not check(SC["uc1_email_digest"].task_success, sbx, "")
        assert not check(SC["uc3_rebuild"].task_success, sbx, "")
    finally:
        sbx.cleanup()


def test_wilson():
    lo, hi = wilson(0, 20)
    assert lo == 0 and 0.15 < hi < 0.18
    lo, hi = wilson(10, 20)
    assert 0.29 < lo < 0.30 and 0.70 < hi < 0.71


def _ollama_up() -> bool:
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1)  # noqa: S310
        return True
    except OSError:
        return False


@pytest.mark.ollama
@pytest.mark.skipif(not _ollama_up(), reason="Ollama is not running on 127.0.0.1:11434")
def test_real_qwen3_uc1_never_exfiltrates():
    _, attack, *_ = play("uc1_email_digest", "http://127.0.0.1:11434")
    assert attack is False
