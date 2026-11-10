"""Append-only JSON Lines decision log (FR-027, NFR-5).

Every entry passes through `mask_json` again at write time (defence in depth, SC-010).
Writes are queued off the critical path; files rotate daily and expire after `retain_days`.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from tainttrap.core.masking import mask_json

SCHEMA_VERSION = 1
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    ms = int(time.time() * 1000)
    value = (ms << 80) | secrets.randbits(80)
    return "".join(_CROCKFORD[(value >> (5 * i)) & 31] for i in reversed(range(26)))


def log_file_for(day: datetime, logs_dir: Path) -> Path:
    return logs_dir / f"decisions-{day:%Y-%m-%d}.jsonl"


class LogWriter:
    def __init__(self, logs_dir: Path, retain_days: int = 90, synchronous: bool = False):
        self.logs_dir = logs_dir
        self.retain_days = retain_days
        self.synchronous = synchronous
        logs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self.purge_expired()
        if not synchronous:
            self._thread = threading.Thread(target=self._run, name="tainttrap-log", daemon=True)
            self._thread.start()

    def prepare(self, entry: dict[str, Any]) -> dict[str, Any]:
        entry = dict(entry)
        entry.setdefault("schema_version", SCHEMA_VERSION)
        entry.setdefault("ts", datetime.now(UTC).isoformat())
        entry.setdefault("entry_id", new_ulid())
        entry.setdefault("session_id", "-")
        entry.setdefault("mode", "observe")
        entry.setdefault("policy_hash", "")
        return mask_json(entry)  # type: ignore[no-any-return]

    def write(self, entry: dict[str, Any]) -> str:
        prepared = self.prepare(entry)
        if self.synchronous:
            self._append(prepared)
        else:
            self._q.put(prepared)
        return str(prepared["entry_id"])

    def _append(self, entry: dict[str, Any]) -> None:
        path = log_file_for(datetime.now(UTC), self.logs_dir)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                self._q.task_done()
                return
            try:
                self._append(item)
            finally:
                self._q.task_done()

    def flush(self) -> None:
        if not self.synchronous:
            self._q.join()

    def close(self) -> None:
        if self._thread is not None:
            self._q.put(None)
            self._thread.join(timeout=5)
            self._thread = None

    def purge_expired(self) -> None:
        cutoff = datetime.now(UTC).date() - timedelta(days=self.retain_days)
        for f in self.logs_dir.glob("decisions-*.jsonl"):
            try:
                day = datetime.strptime(f.stem.removeprefix("decisions-"), "%Y-%m-%d").date()
            except ValueError:
                continue
            if day < cutoff:
                f.unlink(missing_ok=True)


def read_entries(logs_dir: Path, since: datetime | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted(logs_dir.glob("decisions-*.jsonl")):
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since is not None:
                try:
                    if datetime.fromisoformat(e["ts"]) < since:
                        continue
                except (KeyError, ValueError):
                    continue
            out.append(e)
    return out
