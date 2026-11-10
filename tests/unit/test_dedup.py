from tainttrap.client import TaintTrapClient
from tainttrap.core import paths
from tainttrap.daemon.embedded import EmbeddedDaemon
from tainttrap.logstore.writer import read_entries


def test_proxy_reuses_hook_decision():
    with EmbeddedDaemon({"mode": "soft"}):
        hook = TaintTrapClient(session_id="cc", cwd="/p", adapter="claude_code_hook")
        hook.task("Create an issue titled bug")
        first = hook.check("create_issue", {"title": "bug"}, call_id="toolu_1", server="github")
        proxy = TaintTrapClient(session_id="mcp:9", cwd="/p", adapter="mcp_proxy")
        second = proxy.check("create_issue", {"title": "bug"}, call_id="github:1", server="github")
        third = proxy.check("create_issue", {"title": "other"}, call_id="github:2", server="github")
        hook.close()
        proxy.close()
    assert second.effective_outcome == first.effective_outcome
    entries = [e for e in read_entries(paths.logs_dir()) if e["kind"] == "decision"]
    dups = [e for e in entries if e["decision"].get("dedup_of")]
    assert len(dups) == 1 and dups[0]["decision"]["dedup_of"] == first.entry_id
    assert third.entry_id != first.entry_id
