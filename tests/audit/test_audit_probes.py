"""The fail-open audit's probe scripts (copied unchanged from the audit, 2026-10-11), run as
regression tests: each finding T134-T144 stays fixed. A probe prints one line per case; these
tests check the "after" outcome of those lines. Cases for findings not fixed yet are xfail.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.audit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


# Daemon errors as Python's last-resort logging prints them (the probes configure no logging).
DAEMON_ERRORS = (
    "internal error",
    "Task exception was never retrieved",
    "Unhandled exception in client_connected_cb",
    "Exception in callback",
)
# Answers without a rule decision: a probe's ask or block must never be one of these.
NO_DECISION = {"daemon_unavailable", "daemon_timeout", "internal_error", "model_unavailable"}


def _state_dirs() -> set[Path]:
    return set(Path("/tmp").glob("tp*"))  # harness.py: tempfile.mkdtemp(prefix="tp", dir="/tmp")


def probe(name: str, timeout: int = 600, check_logs: bool = True) -> str:
    """Run one probe unchanged. It makes its own state directory; find it afterwards and check
    that the daemon logged no error and that every ask or block was decided by a rule."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TAINTTRAP_")}
    before = _state_dirs()
    r = subprocess.run(
        [sys.executable, str(HERE / f"{name}.py"), str(HERE)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check_logs:
        bad = [m for m in DAEMON_ERRORS if m in r.stderr]
        assert not bad, f"{name}: daemon errors in the probe's output: {bad}"
        created = _state_dirs() - before
        assert created, f"{name}: no state directory found, so its logs were not checked"
        for state in created:
            for f in (state / "home" / "logs").glob("*.jsonl"):
                for raw in f.read_text().splitlines():
                    e = json.loads(raw)
                    d = e.get("decision") if e.get("kind") == "decision" else None
                    if not d or d.get("outcome") == "allow":
                        continue
                    assert d.get("decided_by") != "failure_mode", f"{name}: {d}"
                    codes = set(d.get("reason_codes") or [])
                    assert codes - NO_DECISION, f"{name}: ask/block without a rule code: {d}"
    return r.stdout


def line(out: str, prefix: str) -> str:
    hits = [x for x in out.splitlines() if x.startswith(prefix)]
    assert hits, f"probe printed no line starting with {prefix!r}:\n{out}"
    return hits[0]


@pytest.fixture(scope="module")
def p2() -> str:
    return probe("p2")


@pytest.fixture(scope="module")
def p4() -> str:
    return probe("p4")


@pytest.fixture(scope="module")
def p5() -> str:
    return probe("p5")


def test_baseline_observed_output_is_denied():
    out = probe("p1")
    assert line(out, "soft observed").endswith("deny")
    assert line(out, "strict observed").endswith("deny")


RELAY_CASES = [
    "baseline",
    "id_5.0",  # T134
    "invalid_utf8",  # T135
    "error_response",  # T136
    "tools_list_desc",  # T136
    "init_instructions",  # T136
    "resource_link_desc",  # T136
    "embedded_res_in_prompt",  # T136
    "nested_1200",  # T137
]


@pytest.mark.parametrize("case", RELAY_CASES)
def test_relay_responses_are_observed(case, p4, p5):
    assert line(p4, case).split()[-1] == "block"
    assert line(p5, case).split()[1] == "block"


@pytest.mark.xfail(reason="T149: client batches are forwarded unchecked", strict=True)
def test_relay_client_batch_is_checked(p4):
    assert "forwarded unchecked" not in line(p4, "client_batch_tools_call")


def test_t137_nested_hook_response_is_observed(p2):
    assert line(p2, "A_nested_1200").split()[-1] == "deny"


def test_t139_encoded_output_is_indexed(p2):
    assert line(p2, "C_base64_recipient").split()[-1] == "deny"


@pytest.mark.parametrize("case", ["B_evict_400KB", "B2_evict_8x60KB"])
def test_t144_output_volume_does_not_evict_destinations(case, p2):
    assert line(p2, case).split()[-1] in ("deny", "ask")


def test_t145_middle_of_huge_output_is_not_allowed(p2):
    assert line(p2, "E_middle_of_1.2MB").split()[-1] in ("deny", "ask")


def test_slow_secret_scan_does_not_lose_the_observation():
    assert line(probe("p3"), "send:").split()[-1] == "deny"


def test_t138_oversize_observation_is_not_dropped():
    assert line(probe("p6"), "strict send:").split()[-1] == "deny"


def test_t140_misaligned_base64_secret_is_found():
    out = probe("p7")
    for mode in ("soft", "strict"):
        assert line(out, f"{mode} Z+b64").split()[-1] == "deny"


def test_t141_quoted_redirection_copy_is_tracked():
    out = probe("p10")
    for case in ("soft ansi-c tail", "strict ansi-c tail"):
        assert line(out, case).split()[-1] == "deny"


def test_t148_spoofed_first_party_tool_name():
    out = probe("p9")
    assert line(out, "mcp__notes__read").split()[-1] == "deny"


@pytest.mark.xfail(reason="T148: output trust looked up without the server", strict=True)
def test_t148_spoofed_first_party_tool_name_is_denied():
    assert line(probe("p9"), "mcp__evil__lookup_contact").split()[-1] == "deny"


@pytest.mark.xfail(reason="T147: failure path asks under bypassPermissions", strict=True)
def test_t147_bypass_mode_never_gets_ask():
    assert '"permissionDecision": "ask"' not in probe("p8", check_logs=False)


@pytest.mark.xfail(reason="T152: exceptions in decide are not logged as decisions", strict=True)
def test_t152_decide_exception_is_logged():
    out = probe("p11", check_logs=False)
    assert line(out, "decision entries logged:").split()[-1] != "0"
