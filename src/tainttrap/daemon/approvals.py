"""Pending human approvals held by the daemon (FR-024, FR-025; T081).

Used when an adapter has no approval channel of its own (MCP clients without elicitation).
The 6-digit code is delivered only out of band (OS dialog) on request and never appears in
any socket response; with no GUI channel a daemon approval resolves to deny.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from tainttrap.daemon.integrity import Integrity
from tainttrap.logstore.writer import new_ulid

Answer = Literal["approved", "denied", "timed_out"]
NO_CHANNEL = "no secure approval channel; use hardened mode"


@dataclass
class Pending:
    id: str
    created: float
    expires_at: float
    session_id: str
    entry_id: str
    summary: dict[str, Any]  # tool, server, masked arguments, task, reason
    future: asyncio.Future[tuple[Answer, str]]
    challenge_id: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created": self.created,
            "expires_in_s": max(0, round(self.expires_at - time.time(), 1)),
            "entry_id": self.entry_id,
            **self.summary,
        }


@dataclass
class Approvals:
    integrity: Integrity
    on_resolved: Callable[[Pending, Answer, str], None]
    _pending: dict[str, Pending] = field(default_factory=dict)
    # Answers stay readable for a while so an adapter that asks after the fact still gets them.
    _done: dict[str, tuple[float, Answer, str]] = field(default_factory=dict)
    _changed: asyncio.Event = field(default_factory=asyncio.Event)

    def create(
        self, session_id: str, entry_id: str, summary: dict[str, Any], timeout_s: float
    ) -> Pending:
        loop = asyncio.get_running_loop()
        now = time.time()
        p = Pending(
            id=f"apv_{new_ulid()}",
            created=now,
            expires_at=now + timeout_s,
            session_id=session_id,
            entry_id=entry_id,
            summary=summary,
            future=loop.create_future(),
        )
        self._pending[p.id] = p
        loop.call_later(timeout_s, self._resolve, p.id, "timed_out", "approval timed out")
        notify = getattr(self.integrity.provider, "notify", None)
        if callable(notify):
            notify(
                f"TaintTrap: approval needed for {summary.get('tool')}. Run `tainttrap approvals`."
            )
        self._bump()
        return p

    def _bump(self) -> None:
        self._changed.set()
        self._changed = asyncio.Event()

    def _resolve(self, pid: str, answer: Answer, detail: str) -> None:
        p = self._pending.pop(pid, None)
        if p is None or p.future.done():
            return
        p.future.set_result((answer, detail))
        now = time.time()
        self._done = {k: v for k, v in self._done.items() if now - v[0] < 600}
        self._done[pid] = (now, answer, detail)
        self.on_resolved(p, answer, detail)
        self._bump()

    def list(self) -> list[dict[str, Any]]:
        return [p.public() for p in sorted(self._pending.values(), key=lambda p: p.created)]

    async def wait_changed(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except TimeoutError:
            pass

    def challenge(self, pid: str) -> dict[str, Any]:
        p = self._pending.get(pid)
        if p is None:
            return {"found": False}
        purpose = f"approve {p.summary.get('tool')}: {p.summary.get('reason', '')[:120]}"
        cid, channel, fallback = self.integrity.new_challenge(f"approval {pid}")
        if fallback is not None:
            # Approvals never fall back to showing the code over the socket.
            self._resolve(pid, "denied", NO_CHANNEL)
            return {"found": True, "resolved": "denied", "detail": NO_CHANNEL}
        p.challenge_id = cid
        return {"found": True, "challenge_id": cid, "channel": channel, "purpose": purpose}

    def answer(self, pid: str, challenge_id: str, code: str, approve: bool) -> tuple[bool, str]:
        p = self._pending.get(pid)
        if p is None:
            return False, "no such pending approval"
        ok, detail = self.integrity.verify(challenge_id, code, f"approval {pid}")
        if not ok:
            if "cancelled" in detail:
                self._resolve(pid, "denied", "too many wrong codes")
            return False, detail
        self._resolve(pid, "approved" if approve else "denied", f"by human ({detail})")
        return True, "approved" if approve else "denied"

    async def wait(self, pid: str) -> tuple[Answer, str]:
        p = self._pending.get(pid)
        if p is None:
            done = self._done.get(pid)
            return (done[1], done[2]) if done else ("denied", "no such pending approval")
        return await p.future
