"""Recipients a human has approved, per tool (spec FR-021, PRD "Decisions").

Learned only from explicit, code-confirmed approvals in the daemon's own queue: never from
"the tool ran after an ask" (fail-open, timeouts and unchecked paths would teach attacker
addresses) and never from messages on the check socket (any same-user process can send them).
An address approved for `send_email` is not trusted for `http_post`.
Stored under TAINTTRAP_HOME (self-protected), mode 0600.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SEP = "\t"


def key(tool: str, address: str) -> str:
    return f"{tool}{SEP}{address.strip().casefold()}"


@dataclass
class RecipientStore:
    path: Path
    known: set[str] = field(default_factory=set)  # "tool\taddress"

    @classmethod
    def load(cls, path: Path) -> RecipientStore:
        store = cls(path)
        try:
            data = json.loads(path.read_text())
            for item in data.get("recipients", []):
                store.known.add(key(item["tool"], item["address"]))
        except (OSError, ValueError, AttributeError, KeyError, TypeError):
            pass
        return store

    def add(self, tool: str, addresses: list[str]) -> None:
        new = {key(tool, a) for a in addresses} - self.known
        if new:
            self.known.update(new)
            self._save()

    def revoke(self, address: str, tool: str | None = None) -> int:
        addr = address.strip().casefold()
        drop = {
            k
            for k in self.known
            if k.split(SEP, 1)[1] == addr and (tool is None or k.split(SEP, 1)[0] == tool)
        }
        self.known.difference_update(drop)
        if drop:
            self._save()
        return len(drop)

    def listing(self) -> list[dict[str, str]]:
        return [{"tool": t, "address": a} for t, a in sorted(k.split(SEP, 1) for k in self.known)]

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"recipients": self.listing()}, f, indent=1)
        os.replace(tmp, self.path)
