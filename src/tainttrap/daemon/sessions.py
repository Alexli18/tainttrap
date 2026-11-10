"""Per-session state: task, recent actions, budgets and provenance scopes."""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field

from tainttrap.core.engine import SessionView

SESSION_TTL_S = 24 * 3600


def workspace_scope(cwd: str | None) -> str | None:
    if not cwd:
        return None
    return "ws:" + hashlib.sha256(cwd.encode()).hexdigest()[:16]


@dataclass
class Session:
    session_id: str
    cwd: str | None = None
    task: str | None = None
    task_source: str = "none"
    task_at: float = 0.0
    history: deque[str] = field(default_factory=lambda: deque(maxlen=5))
    recent_actions: deque[str] = field(default_factory=lambda: deque(maxlen=8))
    budget_counts: dict[str, int] = field(default_factory=dict)
    money_spent: float = 0.0
    last_activity: float = field(default_factory=time.monotonic)

    @property
    def scope_ids(self) -> list[str]:
        ids = [self.session_id]
        ws = workspace_scope(self.cwd)
        if ws:
            ids.append(ws)
        return ids

    def view(self) -> SessionView:
        return SessionView(
            task=self.task,
            task_history=tuple(self.history),
            recent_actions=tuple(self.recent_actions),
            scope_ids=tuple(self.scope_ids),
        )


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def known(self, session_id: str) -> bool:
        return session_id in self._sessions

    def get(self, session_id: str, cwd: str | None = None) -> Session:
        s = self._sessions.get(session_id)
        if s is None:
            s = Session(session_id=session_id, cwd=cwd)
            self._sessions[session_id] = s
        if cwd and not s.cwd:
            s.cwd = cwd
        s.last_activity = time.monotonic()
        return s

    def set_task(self, session_id: str, text: str, source: str, cwd: str | None = None) -> Session:
        s = self.get(session_id, cwd)
        if s.task and s.task != text:
            s.history.appendleft(s.task)
        s.task = text
        s.task_source = source
        s.task_at = time.time()
        return s

    def latest_task_for_cwd(self, cwd: str, ttl_min: int) -> str | None:
        best: Session | None = None
        for s in self._sessions.values():
            if s.cwd == cwd and s.task and time.time() - s.task_at <= ttl_min * 60:
                if best is None or s.task_at > best.task_at:
                    best = s
        return best.task if best else None

    def end(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def evict_idle(self) -> list[str]:
        now = time.monotonic()
        idle = [sid for sid, s in self._sessions.items() if now - s.last_activity > SESSION_TTL_S]
        for sid in idle:
            del self._sessions[sid]
        return idle

    def __len__(self) -> int:
        return len(self._sessions)
