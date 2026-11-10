"""Counts for `tainttrap report` (FR-028, T063)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Report:
    checked: int = 0
    allowed: int = 0
    blocked: int = 0
    asked: int = 0
    sent_to_judge: int = 0
    sent_to_human: int = 0
    timed_out: int = 0
    flagged: int = 0
    failure_mode: int = 0
    degraded_sessions: int = 0
    would_be: bool = False
    enforced: int = 0
    by: dict[str, Counter[str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "by"}
        d["by"] = {k: dict(v) for k, v in self.by.items()}
        return d


def build_report(
    entries: Iterable[dict[str, Any]], by: str | None = None, flagged_ids: set[str] | None = None
) -> Report:
    r = Report()
    flagged_ids = flagged_ids or set()
    for e in entries:
        if e.get("kind") == "provenance_degraded":
            r.degraded_sessions += 1
            continue
        if e.get("kind") != "decision":
            continue
        d = e["decision"]
        r.checked += 1
        r.enforced += 1 if d.get("enforced") else 0
        outcome = d["outcome"]
        r.allowed += outcome == "allow"
        r.blocked += outcome == "block"
        r.asked += outcome == "ask"
        r.failure_mode += d.get("decided_by") == "failure_mode"
        for esc in e.get("escalations", []) or d.get("escalations", []) or []:
            r.sent_to_judge += esc.get("to") == "judge"
            r.sent_to_human += esc.get("to") == "human"
        human = e.get("human") or {}
        r.timed_out += human.get("answer") == "timed_out"
        r.flagged += e.get("entry_id") in flagged_ids
        if by:
            key = {
                "risk": (e.get("dossier") or {}).get("tool_risk_class", "?"),
                "tool": (e.get("call") or {}).get("tool_name", "?"),
                "reason": ",".join(d.get("reason_codes", [])) or "-",
            }[by]
            r.by.setdefault(key, Counter())[outcome] += 1
    r.would_be = r.checked > 0 and r.enforced == 0
    return r
