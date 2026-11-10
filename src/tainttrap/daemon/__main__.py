"""`python -m tainttrap.daemon [--foreground]`"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from tainttrap.core import paths
from tainttrap.core.engine import Engine
from tainttrap.core.model.base import AssessmentProvider
from tainttrap.core.model.heuristic import HeuristicProvider
from tainttrap.core.policy import Policy, PolicyError, load_policy
from tainttrap.core.provenance import ProvenanceIndex
from tainttrap.core.registry import Registry
from tainttrap.core.rules import default_rules
from tainttrap.daemon.server import Daemon
from tainttrap.logstore.writer import LogWriter

log = logging.getLogger("tainttrap.daemon")


def select_provider(policy: Policy) -> tuple[AssessmentProvider, str]:
    """ONNX model if installed and verified; otherwise the provenance heuristic."""
    if policy.model.enabled:
        try:
            from tainttrap.core.model.runner import load_onnx_provider  # type: ignore[import-not-found]

            provider, tier = load_onnx_provider(policy)
            return provider, tier
        except Exception as e:  # noqa: BLE001 - no extra installed, no model, integrity failure
            log.warning("model not loaded (%s); using heuristic provider", e)
    return HeuristicProvider(), "none"


def build_daemon(policy: Policy) -> Daemon:
    provider, tier = select_provider(policy)
    engine = Engine(
        registry=Registry.load(paths.user_registry_file()),
        provenance=ProvenanceIndex(
            k=policy.provenance.min_fragment_len, min_entity_len=policy.provenance.min_entity_len
        ),
        provider=provider,
        rules=default_rules(),
        tier=tier,
    )
    return Daemon(
        engine=engine,
        policy=policy,
        log_writer=LogWriter(paths.logs_dir(), policy.logging.retain_days),
    )


async def _main() -> int:
    try:
        policy = load_policy(paths.policy_file())
    except PolicyError as e:
        for p in e.problems:
            print(f"tainttrap: invalid policy: {p}", file=sys.stderr)
        return 1
    daemon = build_daemon(policy)
    await daemon.start()
    pidfile = paths.home_dir() / "daemon.pid"
    pidfile.write_text(str(os.getpid()))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    await daemon.stop()
    daemon.log_writer.close()
    pidfile.unlink(missing_ok=True)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="tainttrap-daemon")
    ap.add_argument("--foreground", action="store_true")
    ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    sys.exit(asyncio.run(_main()))


if __name__ == "__main__":
    main()
