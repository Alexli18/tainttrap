"""Proxy task resolution: _meta -> task file / TAINTTRAP_TASK -> hook task for the same cwd -> unknown."""

import pytest

from tainttrap.adapters.mcp_proxy.relay import Relay
from tainttrap.client import TaintTrapClient
from tainttrap.daemon.embedded import EmbeddedDaemon


async def _noop(_):
    return None


def relay(**kw):
    return Relay(server="s", to_upstream=_noop, to_client=_noop, **kw)


def test_task_file_then_env(tmp_path, monkeypatch):
    f = tmp_path / "t.txt"
    f.write_text("from file")
    monkeypatch.setenv("TAINTTRAP_TASK", "from env")
    assert relay(task_file=f)._static_task() == "from file"
    assert relay()._static_task() == "from env"
    monkeypatch.delenv("TAINTTRAP_TASK")
    assert relay()._static_task() is None


def test_hook_task_for_same_cwd_is_used():
    with EmbeddedDaemon({"mode": "soft"}):
        hook = TaintTrapClient(session_id="cc-session", cwd="/proj")
        hook.task("Email the report to ana@ourco.example", source="hook_prompt")
        proxy = TaintTrapClient(session_id="mcp:1", cwd="/proj", adapter="mcp_proxy")
        d = proxy.check(
            "send_email", {"to": "ana@ourco.example", "body": "r"}, call_id="c1", server="gmail"
        )
        assert d.task.startswith("Email the report") and d.allowed
        other = TaintTrapClient(session_id="mcp:2", cwd="/elsewhere", adapter="mcp_proxy")
        d2 = other.check(
            "send_email", {"to": "ana@ourco.example", "body": "r"}, call_id="c2", server="gmail"
        )
        assert d2.task == ""
        for c in (hook, proxy, other):
            c.close()


def test_meta_task_wins_over_hook_task():
    with EmbeddedDaemon({"mode": "soft"}):
        TaintTrapClient(session_id="cc", cwd="/p").task("Something else entirely")
        proxy = TaintTrapClient(session_id="mcp:3", cwd="/p", adapter="mcp_proxy")
        d = proxy.check(
            "send_email",
            {"to": "x@ourco.example", "body": "b"},
            call_id="c",
            task_hint="Email x@ourco.example",
        )
        assert d.task == "Email x@ourco.example"
        proxy.close()


@pytest.mark.parametrize("mode", ["soft", "strict"])
def test_unknown_task_never_auto_allows_risky_calls(mode):
    with EmbeddedDaemon({"mode": mode}):
        c = TaintTrapClient(session_id="mcp:4", cwd="/nowhere", adapter="mcp_proxy")
        risky = c.check("send_email", {"to": "x@ourco.example", "body": "b"}, call_id="c1")
        read = c.check("read_file", {"path": "a.txt"}, call_id="c2")
        c.close()
    assert risky.effective_outcome != "allow"
    assert "unknown_task" in risky.reason_codes
    assert read.effective_outcome == "allow"
