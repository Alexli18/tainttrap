"""An agent that allocates itself a pseudo-terminal still cannot approve its own call:
the code is only shown out of band (OS dialog), never on the terminal or a socket."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tainttrap.client import TaintTrapClient
from tainttrap.core.model.base import StubProvider
from tainttrap.core.types import Assessment, RiskClass
from tainttrap.daemon.embedded import EmbeddedDaemon

UNSURE = StubProvider(
    Assessment(
        aligned=0.5,
        risk=RiskClass.WRITE_INTERNAL,
        risk_probs={RiskClass.WRITE_INTERNAL: 1.0},
        sensitive_data=0.0,
        needs_human=0.2,
    )
)
CLI = str(Path(sys.executable).parent / "tainttrap")


class SecretDialog:
    name = "dialog"

    def __init__(self):
        self.codes = []

    def deliver(self, code, purpose):
        self.codes.append(code)  # shown only to the human, never to the agent
        return True


@pytest.mark.adversarial
@pytest.mark.skipif(not Path(CLI).exists(), reason="console script not installed")
def test_pty_wrapped_approve_cannot_self_approve():
    dialog = SecretDialog()
    with EmbeddedDaemon({"mode": "soft"}, provider=UNSURE, confirm=dialog):
        c = TaintTrapClient(session_id="agent", cwd="/w")
        c.task("Tidy my notes")
        resp = c._request(
            {
                "op": "check",
                "adapter": "mcp_proxy",
                "session_id": "agent",
                "cwd": "/w",
                "call_id": "c1",
                "tool_name": "write_file",
                "server": "fs",
                "arguments": {"path": "x", "content": "y"},
                "approval_channel": "daemon",
            }
        )
        pid = resp["approval"]["id"]
        spawn = f"import pty, sys; sys.exit(pty.spawn([{CLI!r}, 'approve', {pid!r}]) >> 8)"
        r = subprocess.run(
            [sys.executable, "-c", spawn],
            input="000000\n111111\n222222\n",
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ},
        )
        result = c._request({"op": "await_approval", "id": pid})
        c.close()
    assert r.returncode != 0
    assert result["result"] == "denied"
    assert all(code not in r.stdout + r.stderr for code in dialog.codes)


@pytest.mark.adversarial
@pytest.mark.skipif(not Path(CLI).exists(), reason="console script not installed")
def test_approve_without_tty_refuses():
    r = subprocess.run(
        [CLI, "approve", "apv_x"], capture_output=True, text=True, stdin=subprocess.DEVNULL
    )
    assert r.returncode != 0 and "interactive terminal" in r.stderr
