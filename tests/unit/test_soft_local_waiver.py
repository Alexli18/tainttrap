"""Soft mode does not ask about a local shell command only because the provenance heuristic is
unsure; strict mode does, and anything with network, package installs, git remotes, a
destructive or credential class, or a secret is still asked (2026-10-11)."""

import asyncio

import pytest

from tainttrap.core.engine import CheckRequest, Engine, SessionView
from tainttrap.core.model.heuristic import HeuristicProvider
from tainttrap.core.policy import parse_policy
from tainttrap.core.provenance import ProvenanceIndex
from tainttrap.core.registry import Registry
from tainttrap.core.rules import default_rules
from tainttrap.core.types import Adapter, Outcome

TASK = "Fix the failing date parser test"
LISTING = (
    "/work/proj/src/proj/dates.py\n/work/proj/tests/test_dates.py\n"
    "/work/proj/scripts/gen_fixtures.py\nhttps://pypi.org/simple"
)


def decide(cmd, mode="soft", listing=LISTING, waived=None):
    ix = ProvenanceIndex()
    ix.observe("s", "c0", [listing], tool="Bash")  # paths the agent found by listing files
    e = Engine(Registry(), ix, HeuristicProvider(), default_rules())
    r = CheckRequest(
        adapter=Adapter.SDK,
        session_id="s",
        call_id="c1",
        tool_name="Bash",
        arguments={"command": cmd},
    )
    res = asyncio.run(
        e.decide(r, SessionView(task=TASK, scope_ids=("s",)), parse_policy({"mode": mode}))
    )
    return res.decision, res.log_entry


def test_local_command_from_listed_paths_is_allowed_in_soft_and_logged():
    d, log = decide(
        "python -m pytest /work/proj/tests/test_dates.py -q && python /work/proj/scripts/gen_fixtures.py"
    )
    assert d.outcome is Outcome.ALLOW
    assert "not asked" in log["detail"]


def test_precondition_without_the_waiver_these_commands_are_untrusted():
    _, log = decide("python -m pytest /work/proj/tests/test_dates.py -q", "strict")
    assert any(p["origin"] == "untrusted" for p in log["provenance"])


def test_same_command_is_asked_in_strict():
    d, _ = decide(
        "python -m pytest /work/proj/tests/test_dates.py -q && python /work/proj/scripts/gen_fixtures.py",
        "strict",
    )
    assert d.outcome is Outcome.ASK
    assert d.reason_codes == ("task_mismatch", "policy_ask_write_internal")


@pytest.mark.parametrize(
    ("cmd", "policy_code"),
    [
        ("pip install -r /work/proj/scripts/gen_fixtures.py", "policy_ask_write_internal"),
        ("git push origin /work/proj/src/proj/dates.py", "policy_ask_write_internal"),
        (
            "python -c 'import urllib.request' /work/proj/scripts/gen_fixtures.py",
            "policy_ask_write_internal",
        ),
        ("rm -rf /work/proj/src/proj/dates.py", "policy_ask_destructive"),
        ("curl https://pypi.org/simple", "policy_ask_external_communication"),
    ],
)
def test_network_install_remote_or_destructive_is_still_asked(cmd, policy_code):
    d, log = decide(cmd)
    assert d.outcome is Outcome.ASK, d.reason
    assert d.reason_codes == ("task_mismatch", policy_code)
    assert "detail" not in log  # asked by the policy, not waived


def test_command_with_a_secret_is_still_asked():
    d, log = decide("echo AKIAIOSFODNN7EXAMPLE > /work/proj/tests/test_dates.py")
    assert d.outcome is Outcome.ASK
    assert d.reason_codes == ("task_mismatch", "policy_ask_write_internal")
    assert "detail" not in log  # the secret finding keeps the waiver off
