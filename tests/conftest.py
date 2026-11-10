"""Shared fixtures. Every test runs with isolated TaintTrap dirs, and afterwards every
log/dataset file is scanned for the raw fixture secrets (SC-010)."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
RAW_SECRETS = list(
    json.loads((FIXTURES / "secrets" / "secrets.json").read_text())["secrets"].values()
)


@pytest.fixture(autouse=True)
def ag_dirs(monkeypatch: pytest.MonkeyPatch):
    # Short base path: AF_UNIX socket paths are limited to ~104 bytes on macOS.
    base = Path(tempfile.mkdtemp(prefix="ag", dir="/tmp"))
    for name, sub in (
        ("TAINTTRAP_HOME", "home"),
        ("TAINTTRAP_CONFIG_DIR", "cfg"),
        ("TAINTTRAP_RUNTIME_DIR", "run"),
    ):
        (base / sub).mkdir(mode=0o700)
        monkeypatch.setenv(name, str(base / sub))
    yield base
    leaks = []
    for sub in ("home/logs", "home/datasets"):
        d = base / sub
        if not d.exists():
            continue
        for f in d.rglob("*"):
            if f.is_file():
                text = f.read_text(errors="ignore")
                leaks += [(f.name, s[:12]) for s in RAW_SECRETS if s in text]
    assert not leaks, f"unmasked secrets in logs: {leaks}"


@pytest.fixture
def secrets_fixture() -> dict[str, dict[str, str]]:
    return json.loads((FIXTURES / "secrets" / "secrets.json").read_text())


class _ErrorRecords(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        m = item.get_closest_marker("daemon_errors_expected")
        if m is not None and not m.args:
            raise pytest.UsageError(
                f"{item.nodeid}: daemon_errors_expected needs the expected error type names"
            )


def _error_type(record: logging.LogRecord) -> str:
    if record.exc_info and record.exc_info[1] is not None:
        return type(record.exc_info[1]).__name__
    return record.getMessage()


@pytest.fixture(autouse=True)
def no_daemon_internal_errors(request: pytest.FixtureRequest):
    """A daemon that hits an internal error (engine, rules, dossier, a crashed request task)
    answers "unavailable", which the hook turns into a question: a test expecting ask would
    then pass for the wrong reason. Any such error fails the test, whatever was decided.
    `@pytest.mark.daemon_errors_expected("ConnectionResetError", ...)` names the errors a test
    provokes on purpose: each must occur, and any other still fails the test."""
    handler = _ErrorRecords()
    loggers = [logging.getLogger("tainttrap"), logging.getLogger("asyncio")]
    for lg in loggers:
        lg.addHandler(handler)
    yield
    for lg in loggers:
        lg.removeHandler(handler)
    marker = request.node.get_closest_marker("daemon_errors_expected")
    expected = set(marker.args) if marker else set()
    seen = [_error_type(r) for r in handler.records]
    unexpected = [t for t in seen if t not in expected]
    if unexpected:
        pytest.fail(f"daemon internal error during the test ({len(seen)}): {unexpected[0]}")
    missing = expected - set(seen)
    if missing:
        pytest.fail(f"expected daemon errors did not occur: {sorted(missing)}")
