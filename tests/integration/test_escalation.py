"""US4: judge, then human; timeouts; approvals over the admin socket (T075, T081)."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tainttrap.cli.admin import admin_request
from tainttrap.client import TaintTrapClient
from tainttrap.core import paths
from tainttrap.core.model.base import StubProvider
from tainttrap.core.types import Assessment, RiskClass
from tainttrap.daemon.embedded import EmbeddedDaemon
from tainttrap.logstore.writer import read_entries

UNSURE = StubProvider(
    Assessment(
        aligned=0.5,
        risk=RiskClass.WRITE_INTERNAL,
        risk_probs={RiskClass.WRITE_INTERNAL: 1.0},
        sensitive_data=0.0,
        needs_human=0.2,
    )
)
CALL = ("write_file", {"path": "notes.txt", "content": "hi"})


class JudgeServer:
    """Stub judge speaking both OpenAI-compatible and Anthropic shapes."""

    def __init__(self, reply="allow", delay=0.0):
        self.reply, self.delay, self.hits = reply, delay, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.hits.append((self.path, body))
                time.sleep(outer.delay)
                text = (
                    outer.reply
                    if outer.reply.startswith(("{", "not"))
                    else json.dumps(
                        {"decision": outer.reply, "aligned": 0.9, "reason": "stub judge"}
                    )
                )
                if self.path.endswith("/v1/messages"):
                    resp = {"content": [{"type": "text", "text": text}]}
                else:
                    resp = {"choices": [{"message": {"content": text}}]}
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def judge_policy(self, provider="openai_compatible", **extra):
        endpoint = f"{self.url}/v1" if provider == "openai_compatible" else self.url
        return {
            "judge": {
                "enabled": True,
                "provider": provider,
                "endpoint": endpoint,
                "model": "m",
                **extra,
            }
        }


@pytest.fixture
def judge():
    j = JudgeServer()
    yield j
    j.srv.shutdown()


@pytest.mark.parametrize("provider", ["openai_compatible", "anthropic"])
@pytest.mark.parametrize("reply, outcome", [("allow", "allow"), ("deny", "block"), ("ask", "ask")])
def test_strict_unsure_goes_to_judge(judge, provider, reply, outcome):
    judge.reply = reply
    with EmbeddedDaemon({"mode": "strict", **judge.judge_policy(provider)}, provider=UNSURE):
        c = TaintTrapClient(session_id="j", cwd="/w")
        c.task("Tidy my notes")
        d = c.check(*CALL, call_id="c1")
        c.close()
    assert d.effective_outcome == outcome and d.decided_by == "judge"
    assert judge.hits and judge.hits[0][0].endswith(
        "/v1/messages" if provider == "anthropic" else "/chat/completions"
    )
    entries = [e for e in read_entries(paths.logs_dir()) if e["kind"] == "decision"]
    assert entries[-1]["judge_assessment"]["model_id"].endswith(":m")


@pytest.mark.parametrize("reply, delay", [("not json at all", 0.0), ("allow", 3.0)])
def test_judge_garbage_or_timeout_goes_to_human(judge, reply, delay):
    judge.reply, judge.delay = reply, delay
    with EmbeddedDaemon({"mode": "strict", **judge.judge_policy(timeout_ms=1000)}, provider=UNSURE):
        c = TaintTrapClient(session_id="j2", cwd="/w")
        c.task("Tidy my notes")
        d = c.check(*CALL, call_id="c1")
        c.close()
    assert d.effective_outcome == "ask" and "judge_unsure" in d.reason_codes


@pytest.mark.parametrize(
    "mode, expected", [("soft", "ask"), ("strict", "ask"), ("observe", "allow")]
)
def test_judge_off_or_soft_never_contacted(judge, mode, expected):
    policy = {"mode": mode}
    if mode == "soft":
        policy.update(judge.judge_policy())  # enabled, but soft mode never uses it
    with EmbeddedDaemon(policy, provider=UNSURE):
        c = TaintTrapClient(session_id="j3", cwd="/w")
        c.task("Tidy my notes")
        d = c.check(*CALL, call_id="c1")
        c.close()
    assert d.effective_outcome == expected and judge.hits == []


class StubConfirm:
    name = "stub"

    def __init__(self, deliver=True):
        self.codes, self.ok = [], deliver

    def deliver(self, code, purpose):
        self.codes.append(code)
        return self.ok


def _ask_with_daemon_channel(c, call_id):
    resp = c._request(
        {
            "op": "check",
            "adapter": "mcp_proxy",
            "session_id": c.session_id,
            "cwd": c.cwd,
            "call_id": call_id,
            "tool_name": CALL[0],
            "server": "fs",
            "arguments": CALL[1],
            "approval_channel": "daemon",
        }
    )
    assert resp["decision"]["effective_outcome"] == "ask"
    assert "policy_ask_write_internal" in resp["decision"]["reason_codes"]
    return resp["approval"]["id"]


def test_daemon_approval_approve_and_log():
    confirm = StubConfirm()
    with EmbeddedDaemon({"mode": "soft"}, provider=UNSURE, confirm=confirm):
        c = TaintTrapClient(session_id="a1", cwd="/w")
        c.task("Tidy my notes")
        pid = _ask_with_daemon_channel(c, "c1")
        pending = admin_request("approvals")["pending"]
        assert [p["id"] for p in pending] == [pid] and "code" not in json.dumps(pending)
        ch = admin_request("approval_challenge", id=pid)
        assert "code" not in ch
        assert admin_request(
            "approve", id=pid, challenge_id=ch["challenge_id"], code=confirm.codes[-1]
        )["ok"]
        waited = c._request({"op": "await_approval", "id": pid})
        c.close()
    assert waited["result"] == "approved"
    approvals = [e for e in read_entries(paths.logs_dir()) if e["kind"] == "approval"]
    assert (
        approvals[-1]["human"]["answer"] == "approved"
        and approvals[-1]["human"]["channel"] == "approvals_cli"
    )


def test_guessing_codes_denies():
    with EmbeddedDaemon({"mode": "soft"}, provider=UNSURE, confirm=StubConfirm()):
        c = TaintTrapClient(session_id="a2", cwd="/w")
        c.task("Tidy my notes")
        pid = _ask_with_daemon_channel(c, "c1")
        ch = admin_request("approval_challenge", id=pid)
        for _ in range(3):
            assert not admin_request(
                "approve", id=pid, challenge_id=ch["challenge_id"], code="123456"
            )["ok"]
        assert c._request({"op": "await_approval", "id": pid})["result"] == "denied"
        c.close()


def test_no_gui_channel_denies():
    with EmbeddedDaemon({"mode": "soft"}, provider=UNSURE, confirm=StubConfirm(deliver=False)):
        c = TaintTrapClient(session_id="a3", cwd="/w")
        c.task("Tidy my notes")
        pid = _ask_with_daemon_channel(c, "c1")
        ch = admin_request("approval_challenge", id=pid)
        assert ch["resolved"] == "denied" and "code" not in ch
        c.close()


@pytest.mark.slow
def test_timeout_and_fifo():
    with EmbeddedDaemon(
        {"mode": "soft", "human": {"timeout_s": 5}}, provider=UNSURE, confirm=StubConfirm()
    ):
        clients = [TaintTrapClient(session_id=f"f{i}", cwd="/w") for i in range(3)]
        ids = []
        for i, c in enumerate(clients):
            c.task("Tidy my notes")
            ids.append(_ask_with_daemon_channel(c, f"c{i}"))
            time.sleep(0.05)
        assert [p["id"] for p in admin_request("approvals")["pending"]] == ids  # FIFO
        with ThreadPoolExecutor(3) as ex:
            results = list(
                ex.map(
                    lambda ci: ci[0]._request({"op": "await_approval", "id": ci[1]}),
                    zip(clients, ids, strict=True),
                )
            )
        for c in clients:
            c.close()
    assert [r["result"] for r in results] == ["timed_out"] * 3
    assert all(r["detail"] == "approval timed out" for r in results)
