"""Importable Python client for the TaintTrap daemon (check socket only).

Standard library only, so custom agents gain no dependencies. Used by the Claude Agent SDK
adapter, custom agents and the local Ollama test agent (research R-13).

    from tainttrap.client import TaintTrapClient
    ag = TaintTrapClient(session_id="run-1", cwd="/repo")
    ag.task("Summarize README.md")
    d = ag.check("send_email", {"to": "a@b.c", "body": "hi"}, call_id="c1")
    if d.allowed: ...
    ag.observe("c1", "send_email", result)
"""

from __future__ import annotations

import asyncio
import itertools
import json
import os
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_RIDS = itertools.count(1)


def runtime_dir() -> Path:
    override = os.environ.get("TAINTTRAP_RUNTIME_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches" / "tainttrap"
    elif os.environ.get("XDG_RUNTIME_DIR"):
        base = Path(os.environ["XDG_RUNTIME_DIR"]) / "tainttrap"
    else:
        base = Path(f"/tmp/tainttrap-{os.getuid()}")  # noqa: S108
    if len(str(base / "admin.sock")) > 100:
        base = Path(f"/tmp/tt-{os.getuid()}")  # noqa: S108
    return base


def hook_settings() -> dict[str, Any] | None:
    try:
        data = json.loads((runtime_dir() / "hook.json").read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


@dataclass(frozen=True)
class ClientDecision:
    outcome: str  # allow | ask | block
    effective_outcome: str
    enforced: bool
    reason: str
    reason_codes: tuple[str, ...] = ()
    decided_by: str = ""
    entry_id: str = ""
    task: str = ""
    error: str | None = None
    hint: str = ""
    blocked_parts: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.effective_outcome == "allow"

    @property
    def needs_approval(self) -> bool:
        return self.effective_outcome == "ask"


def failure_decision(error: str, code: str = "daemon_unavailable") -> ClientDecision:
    """The daemon could not answer: no rules ran. Only observe mode lets the call through;
    otherwise ask (or block with `fail_closed_action: block`). A missing or unreadable
    hook.json counts as a protecting mode. `failure_mode` is about an unavailable model and is
    applied by the daemon, not here."""
    s = hook_settings()
    codes = (code,)  # daemon_unavailable | daemon_timeout | internal_error
    if s is not None and s.get("mode") == "observe":
        return ClientDecision(
            "allow",
            "allow",
            False,
            "TaintTrap unavailable (observe mode)",
            codes,
            "failure_mode",
            error=error,
        )
    outcome = "block" if (s or {}).get("fail_closed_action") == "block" else "ask"
    return ClientDecision(
        outcome,
        outcome,
        True,
        f"TaintTrap unavailable [{code}]: no checks ran",
        codes,
        "failure_mode",
        error=error,
    )


@dataclass
class TaintTrapClient:
    session_id: str
    cwd: str | None = None
    adapter: str = "sdk"
    timeout_s: float = 30.0
    socket_path: Path | None = None
    _sock: socket.socket | None = field(default=None, repr=False)
    _buf: bytes = field(default=b"", repr=False)
    _started: bool = field(default=False, repr=False)

    def _path(self) -> Path:
        return self.socket_path or runtime_dir() / "check.sock"

    def _connect(self) -> socket.socket:
        if self._sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout_s)
            s.connect(str(self._path()))
            self._sock = s
        return self._sock

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._started and payload.get("session_id") == self.session_id:
            # Announce the session once, so the daemon knows it starts under it; a daemon that
            # never saw the start (it restarted since) treats the session as degraded.
            self._started = True
            self._send(
                {
                    "op": "session_start",
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "source": "sdk",
                }
            )
        return self._send(payload)

    def _send(self, payload: dict[str, Any]) -> dict[str, Any]:
        rid = str(next(_RIDS))
        msg = {"v": 1, "rid": rid, **payload}
        sock = self._connect()
        try:
            sock.sendall((json.dumps(msg) + "\n").encode())
            while True:
                while b"\n" not in self._buf:
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise ConnectionError("daemon closed the connection")
                    self._buf += chunk
                line, self._buf = self._buf.split(b"\n", 1)
                resp = json.loads(line)
                if resp.get("rid") == rid:
                    return resp  # type: ignore[no-any-return]
        except (OSError, ValueError):
            self.close()
            raise

    def task(self, text: str, source: str = "proxy_config") -> None:
        try:
            self._request(
                {
                    "op": "task",
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "text": text,
                    "source": source,
                }
            )
        except (OSError, ValueError, ConnectionError):
            pass

    def observe(self, call_id: str, tool_name: str, response: Any) -> None:
        try:
            self._request(
                {
                    "op": "observe",
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "response": response,
                }
            )
        except (OSError, ValueError, ConnectionError):
            pass

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        call_id: str,
        server: str | None = None,
        task_hint: str | None = None,
    ) -> ClientDecision:
        try:
            resp = self._request(
                {
                    "op": "check",
                    "adapter": self.adapter,
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "server": server,
                    "arguments": arguments,
                    "task_hint": task_hint,
                    "deadline_ms": int(self.timeout_s * 1000) - 500,
                }
            )
        except (OSError, ValueError, ConnectionError) as e:
            code = "daemon_timeout" if isinstance(e, TimeoutError) else "daemon_unavailable"
            return failure_decision(f"{type(e).__name__}: {e}", code)
        if not resp.get("ok"):
            err = str(resp.get("error"))
            code = "daemon_timeout" if err == "daemon_timeout" else "internal_error"
            return failure_decision(f"{err}: {resp.get('detail', '')}", code)
        d = resp["decision"]
        return ClientDecision(
            outcome=d["outcome"],
            effective_outcome=d["effective_outcome"],
            enforced=d["enforced"],
            reason=d["reason"],
            reason_codes=tuple(d.get("reason_codes", ())),
            decided_by=d.get("decided_by", ""),
            entry_id=d.get("entry_id", ""),
            task=d.get("task", ""),
            hint=d.get("hint", ""),
            blocked_parts=tuple(d.get("blocked_parts", ())),
        )

    def end(self) -> None:
        try:
            self._request({"op": "session_end", "session_id": self.session_id})
        except (OSError, ValueError, ConnectionError):
            pass

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._buf = b""

    # async twins (run the blocking calls in a thread)
    async def atask(self, text: str, source: str = "proxy_config") -> None:
        await asyncio.to_thread(self.task, text, source)

    async def aobserve(self, call_id: str, tool_name: str, response: Any) -> None:
        await asyncio.to_thread(self.observe, call_id, tool_name, response)

    async def acheck(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        call_id: str,
        server: str | None = None,
        task_hint: str | None = None,
    ) -> ClientDecision:
        return await asyncio.to_thread(self.check, tool_name, arguments, call_id, server, task_hint)
