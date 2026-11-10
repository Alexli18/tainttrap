"""Remembered recipients: learned only from code-confirmed daemon approvals, per tool."""

from click.testing import CliRunner

from tainttrap.cli.admin import admin_request
from tainttrap.cli.main import cli
from tainttrap.client import TaintTrapClient
from tainttrap.daemon.embedded import EmbeddedDaemon

CONTACT = '{"name": "Ana", "email": "ana@ourco.example"}'


class StubConfirm:
    name = "stub"

    def __init__(self):
        self.codes = []

    def deliver(self, code, purpose):
        self.codes.append(code)
        return True


def check(c, tool, call_id, channel=None):
    req = {
        "op": "check",
        "adapter": "sdk",
        "session_id": c.session_id,
        "cwd": c.cwd,
        "call_id": call_id,
        "tool_name": tool,
        "arguments": {"to": "ana@ourco.example", "subject": "r", "body": "Q3"},
    }
    if channel:
        req["approval_channel"] = channel
    return c._request(req)


def setup(c):
    c.task("Email the Q3 report to Ana")
    c.observe("lookup1", "lookup_contact", CONTACT)


def test_code_confirmed_approval_teaches_per_tool():
    confirm = StubConfirm()
    with EmbeddedDaemon({"mode": "soft"}, confirm=confirm):
        c = TaintTrapClient(session_id="r1", cwd="/w")
        setup(c)
        first = check(c, "send_email", "c1", channel="daemon")
        assert first["decision"]["effective_outcome"] == "ask"
        assert "recipient_from_directory" in first["decision"]["reason_codes"]
        pid = first["approval"]["id"]
        ch = admin_request("approval_challenge", id=pid)
        assert admin_request(
            "approve", id=pid, challenge_id=ch["challenge_id"], code=confirm.codes[-1]
        )["ok"]

        again = check(c, "send_email", "c2")
        assert again["decision"]["effective_outcome"] == "allow"
        other_tool = check(c, "send_message", "c3")  # approved for send_email only
        assert other_tool["decision"]["effective_outcome"] == "ask"
        assert "recipient_from_directory" in other_tool["decision"]["reason_codes"]
        assert admin_request("recipients")["recipients"] == [
            {"tool": "send_email", "address": "ana@ourco.example"}
        ]

        assert admin_request("revoke_recipient", address="ana@ourco.example")["removed"] == 1
        revoked = check(c, "send_email", "c4")["decision"]
        assert revoked["effective_outcome"] == "ask"
        assert "recipient_from_directory" in revoked["reason_codes"]
        c.close()


def test_tool_running_after_ask_or_socket_message_does_not_teach():
    with EmbeddedDaemon({"mode": "soft"}, confirm=StubConfirm()):
        c = TaintTrapClient(session_id="r2", cwd="/w")
        setup(c)
        d = check(c, "send_email", "c1")
        assert d["decision"]["effective_outcome"] == "ask"
        assert "recipient_from_directory" in d["decision"]["reason_codes"]
        c.observe("c1", "send_email", "sent")  # e.g. fail-open or an unchecked path ran it
        c._request(
            {
                "op": "human_answer",
                "session_id": "r2",
                "entry_id": d["decision"]["entry_id"],
                "answer": "approved",
                "channel": "elicitation",
            }
        )  # forgeable by any local process
        again = check(c, "send_email", "c2")["decision"]
        assert again["effective_outcome"] == "ask"
        assert "recipient_from_directory" in again["reason_codes"]
        assert admin_request("recipients")["recipients"] == []
        c.close()


def test_recipients_cli_list():
    with EmbeddedDaemon():
        r = CliRunner().invoke(cli, ["recipients", "list"])
    assert r.exit_code == 0 and "no remembered recipients" in r.output
