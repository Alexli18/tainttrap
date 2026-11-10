"""Run a Daemon on a background event loop inside the current process.

Used by tests and by the local-agent runner when no external daemon is running.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from tainttrap.core import paths
from tainttrap.core.engine import Engine
from tainttrap.core.model.base import AssessmentProvider
from tainttrap.core.model.heuristic import HeuristicProvider
from tainttrap.core.policy import Policy, parse_policy
from tainttrap.core.provenance import ProvenanceIndex
from tainttrap.core.registry import Registry
from tainttrap.core.rules import default_rules
from tainttrap.daemon.server import Daemon
from tainttrap.logstore.writer import LogWriter


class EmbeddedDaemon:
    def __init__(
        self,
        policy: Policy | dict[str, Any] | None = None,
        provider: AssessmentProvider | None = None,
        synchronous_log: bool = True,
        confirm: Any = None,
    ) -> None:
        self.confirm = confirm
        self.policy = policy if isinstance(policy, Policy) else parse_policy(policy or {})
        self.provider = provider or HeuristicProvider()
        self.synchronous_log = synchronous_log
        self.loop = asyncio.new_event_loop()
        self.daemon: Daemon | None = None
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def __enter__(self) -> EmbeddedDaemon:
        self._thread.start()
        engine = Engine(
            Registry.load(paths.user_registry_file()),
            ProvenanceIndex(
                k=self.policy.provenance.min_fragment_len,
                min_entity_len=self.policy.provenance.min_entity_len,
            ),
            self.provider,
            default_rules(),
        )
        writer = LogWriter(paths.logs_dir(), self.policy.logging.retain_days, self.synchronous_log)
        self.daemon = Daemon(engine=engine, policy=self.policy, log_writer=writer)
        if self.confirm is not None:
            from tainttrap.daemon.integrity import Integrity

            self.daemon.integrity = Integrity(provider=self.confirm)
        asyncio.run_coroutine_threadsafe(self.daemon.start(), self.loop).result(10)
        return self

    def run(self, coro: Any, timeout: float = 30) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def set_policy(self, policy: Policy | dict[str, Any]) -> None:
        assert self.daemon is not None
        p = policy if isinstance(policy, Policy) else parse_policy(policy)
        self.loop.call_soon_threadsafe(self.daemon.apply_policy, p)

    def __exit__(self, *exc: object) -> None:
        assert self.daemon is not None
        self.run(self.daemon.stop(), 10)
        self.daemon.log_writer.close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(10)
