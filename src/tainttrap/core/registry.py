"""Trusted tool registry (FR-009..FR-011, NFR-9).

Descriptions and risk classes come only from the packaged catalog and the user's
registry file, never from MCP servers. Lookup order: exact user entry -> exact built-in ->
user glob -> built-in glob -> `unknown`.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from tainttrap.core.types import ArgRule, RiskClass, ToolRegistryEntry

SEVERITY = {
    RiskClass.READ_ONLY: 0,
    RiskClass.WRITE_INTERNAL: 1,
    RiskClass.EXTERNAL_COMMUNICATION: 2,
    RiskClass.CREDENTIAL_ACCESS: 3,
    RiskClass.FINANCIAL: 4,
    RiskClass.DESTRUCTIVE: 5,
    RiskClass.UNKNOWN: 2,
}


def _parse_entries(data: Any, source: str) -> list[ToolRegistryEntry]:
    entries = []
    for raw in (data or {}).get("tools", []):
        raw = dict(raw)
        raw["arg_risk_overrides"] = tuple(ArgRule(**r) for r in raw.get("arg_risk_overrides", []))
        raw["sensitive_args"] = tuple(raw.get("sensitive_args", ()))
        raw["source"] = source
        entries.append(ToolRegistryEntry(**raw))
    return entries


@cache
def builtin_entries() -> tuple[ToolRegistryEntry, ...]:
    out: list[ToolRegistryEntry] = []
    pkg = resources.files("tainttrap.data.registry")
    for item in sorted(pkg.iterdir(), key=lambda p: p.name):
        if item.name.endswith(".yaml"):
            out.extend(_parse_entries(yaml.safe_load(item.read_text()), "builtin"))
    return tuple(out)


@dataclass(frozen=True)
class _Compiled:
    entry: ToolRegistryEntry
    overrides: tuple[tuple[str, re.Pattern[str], RiskClass], ...]


def _compile(e: ToolRegistryEntry) -> _Compiled:
    return _Compiled(
        e, tuple((o.arg, re.compile(o.pattern), o.risk_class) for o in e.arg_risk_overrides)
    )


class Registry:
    def __init__(self, user_entries: list[ToolRegistryEntry] | None = None):
        self._user = [_compile(e) for e in (user_entries or [])]
        self._builtin = [_compile(e) for e in builtin_entries()]

    @classmethod
    def load(cls, user_file: Path | None) -> Registry:
        user: list[ToolRegistryEntry] = []
        if user_file and user_file.exists():
            user = _parse_entries(yaml.safe_load(user_file.read_text()), "user")
        return cls(user)

    @staticmethod
    def _key_match(c: _Compiled, name: str, server: str | None, glob: bool) -> bool:
        if (c.entry.server or None) != (server or None):
            return False
        is_glob = any(ch in c.entry.name for ch in "*?[")
        if glob:
            return is_glob and fnmatch.fnmatchcase(name, c.entry.name)
        return not is_glob and c.entry.name == name

    def find(self, tool_name: str, server: str | None = None) -> _Compiled | None:
        for pool, glob in (
            (self._user, False),
            (self._builtin, False),
            (self._user, True),
            (self._builtin, True),
        ):
            for c in pool:
                if self._key_match(c, tool_name, server, glob):
                    return c
        return None

    def lookup(
        self, tool_name: str, server: str | None, arguments: dict[str, Any]
    ) -> tuple[ToolRegistryEntry | None, RiskClass]:
        c = self.find(tool_name, server)
        if c is None and server is not None:
            # An MCP tool not listed for its server: fall back to our generic entry of that name.
            c = self.find(tool_name, None)
        if c is None:
            return None, RiskClass.UNKNOWN
        risk = c.entry.risk_class
        for arg, rx, cls in c.overrides:
            value = arguments.get(arg)
            if isinstance(value, str) and rx.search(value) and SEVERITY[cls] > SEVERITY[risk]:
                risk = cls
        return c.entry, risk

    def all_entries(self) -> list[ToolRegistryEntry]:
        return [c.entry for c in self._user + self._builtin]
