"""US4 in the MCP proxy: approval through the client (elicitation) or the daemon (T077)."""

import json
import threading
import time

from tainttrap.cli.admin import admin_request
from tainttrap.daemon.embedded import EmbeddedDaemon
from tests.integration.mcp_client import ProxyClient

CAPS = {"io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}
MODERN = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
APPROVE = {"action": "accept", "content": {"decision": "approve"}}


def _task(tmp_path):
    f = tmp_path / "task.txt"
    f.write_text("Tidy up")
    return f


def _call(c, rid, params):
    c.send_raw(
        json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params}).encode()
    )
    return json.loads(c.read_raw())


def test_modern_input_required_then_approved(tmp_path):
    counter = tmp_path / "count"
    with EmbeddedDaemon({"mode": "soft"}):
        c = ProxyClient(counter, task_file=_task(tmp_path))
        c.handshake()
        first = _call(
            c, 10, {"name": "mystery_tool", "arguments": {"x": 1}, "_meta": {**MODERN, **CAPS}}
        )
        res = first["result"]
        assert res["resultType"] == "input_required"
        form = res["inputRequests"]["tainttrap/approval"]
        assert (
            form["method"] == "elicitation/create"
            and "needs your approval" in form["params"]["message"]
        )
        state = res["requestState"]
        assert int(counter.read_text()) == 0

        tampered = _call(
            c,
            11,
            {
                "name": "mystery_tool",
                "arguments": {"x": 2},
                "_meta": MODERN,
                "inputResponses": {"tainttrap/approval": APPROVE},
                "requestState": state,
            },
        )
        assert (
            tampered["result"]["isError"]
            and "different call" in tampered["result"]["content"][0]["text"]
        )

        ok = _call(
            c,
            12,
            {
                "name": "mystery_tool",
                "arguments": {"x": 1},
                "_meta": MODERN,
                "inputResponses": {"tainttrap/approval": APPROVE},
                "requestState": state,
            },
        )
        assert ok["result"]["isError"] is False  # the server's own answer
        assert int(counter.read_text()) == 1
        c.close()


def test_modern_denied(tmp_path):
    counter = tmp_path / "count"
    with EmbeddedDaemon({"mode": "soft"}):
        c = ProxyClient(counter, task_file=_task(tmp_path))
        c.handshake()
        state = _call(
            c, 10, {"name": "mystery_tool", "arguments": {}, "_meta": {**MODERN, **CAPS}}
        )["result"]["requestState"]
        r = _call(
            c,
            11,
            {
                "name": "mystery_tool",
                "arguments": {},
                "_meta": MODERN,
                "requestState": state,
                "inputResponses": {"tainttrap/approval": {"action": "decline"}},
            },
        )
        c.close()
    assert r["result"]["isError"] and int(counter.read_text()) == 0


def test_legacy_elicitation_create(tmp_path):
    counter = tmp_path / "count"
    with EmbeddedDaemon({"mode": "soft"}):
        c = ProxyClient(counter, legacy_only=True, task_file=_task(tmp_path))
        c.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {}},
                "clientInfo": {"name": "t"},
            },
        )
        c.send_raw(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": {"name": "mystery_tool", "arguments": {}},
                }
            ).encode()
        )
        ask = json.loads(c.read_raw())
        assert ask["method"] == "elicitation/create" and ask["id"].startswith("tt-")
        c.send_raw(json.dumps({"jsonrpc": "2.0", "id": ask["id"], "result": APPROVE}).encode())
        result = json.loads(c.read_raw())
        assert result["id"] == 20 and result["result"]["isError"] is False
        assert int(counter.read_text()) == 1
        c.close()


class StubConfirm:
    name = "stub"

    def __init__(self):
        self.codes = []

    def deliver(self, code, purpose):
        self.codes.append(code)
        return True


def test_no_elicitation_uses_daemon_approval(tmp_path):
    counter = tmp_path / "count"
    confirm = StubConfirm()
    with EmbeddedDaemon({"mode": "soft"}, confirm=confirm):
        c = ProxyClient(counter, legacy_only=True, task_file=_task(tmp_path))
        c.request(
            "initialize",
            {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t"}},
        )

        def human():
            for _ in range(100):
                pending = admin_request("approvals")["pending"]
                if pending:
                    ch = admin_request("approval_challenge", id=pending[0]["id"])
                    admin_request(
                        "approve",
                        id=pending[0]["id"],
                        challenge_id=ch["challenge_id"],
                        code=confirm.codes[-1],
                    )
                    return
                time.sleep(0.05)

        t = threading.Thread(target=human)
        t.start()
        r = c.call("mystery_tool", {})
        t.join()
        c.close()
    assert r["result"]["isError"] is False and int(counter.read_text()) == 1
