"""Secret detection over tool-call arguments (FR-013, research R-05).

Vendored gitleaks/Betterleaks rules run behind a lower-cased keyword prefilter,
with Shannon entropy on the captured secret and a skip list for hash/UUID look-alikes.
A second detector flags references to known credential files (FR-013, second clause).
"""

from __future__ import annotations

import math
import re
import tomllib
import warnings
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any, Literal

Confidence = Literal["high", "medium"]

_HEX_LOOKALIKE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SECRET_KEYWORDS = re.compile(
    r"(?i)(secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|credential|auth)"
)
_KEYWORD_WINDOW = 20


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    confidence: Confidence
    start: int
    end: int
    type: str

    @property
    def placeholder(self) -> str:
        return f"<SECRET:{self.type}>"


@dataclass(frozen=True)
class _Rule:
    id: str
    regex: re.Pattern[str]
    keywords: tuple[str, ...]
    confidence: Confidence
    entropy: float | None
    secret_group: int | None
    stopwords: tuple[str, ...]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@cache
def _load_rules() -> tuple[_Rule, ...]:
    raw = tomllib.loads(
        resources.files("tainttrap.data.secrets").joinpath("rules.toml").read_text()
    )
    rules = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        for r in raw["rules"]:
            rules.append(
                _Rule(
                    id=r["id"],
                    regex=re.compile(r["regex"]),
                    keywords=tuple(r.get("keywords", ())),
                    confidence=r["confidence"],
                    entropy=r.get("entropy"),
                    secret_group=r.get("secret_group"),
                    stopwords=tuple(w.lower() for w in r.get("stopwords", ())),
                )
            )
    return tuple(rules)


def _secret_span(rule: _Rule, m: re.Match[str]) -> tuple[int, int]:
    if rule.secret_group and rule.secret_group <= (m.re.groups or 0):
        if m.group(rule.secret_group) is not None:
            return m.span(rule.secret_group)
    # gitleaks convention: first capturing group that matched, else the whole match.
    for g in range(1, (m.re.groups or 0) + 1):
        if m.group(g) is not None:
            return m.span(g)
    return m.span()


def _is_lookalike(text: str, secret: str, start: int) -> bool:
    if _HEX_LOOKALIKE.match(secret) or _UUID.match(secret):
        window = text[max(0, start - _KEYWORD_WINDOW) : start]
        return not _SECRET_KEYWORDS.search(window)
    return False


def scan_value(text: str, disabled: frozenset[str] = frozenset()) -> list[SecretFinding]:
    """Return non-overlapping findings, highest confidence first on overlap."""
    if not text:
        return []
    lowered = text.lower()
    found: list[SecretFinding] = []
    for rule in _load_rules():
        if rule.id in disabled:
            continue
        if rule.keywords and not any(k in lowered for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            start, end = _secret_span(rule, m)
            secret = text[start:end]
            if not secret:
                continue
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if rule.stopwords and any(w in secret.lower() for w in rule.stopwords):
                continue
            if _is_lookalike(text, secret, start):
                continue
            found.append(SecretFinding(rule.id, rule.confidence, start, end, rule.id))
    found.extend(scan_sensitive_paths(text))
    return _dedupe(found)


def _dedupe(found: list[SecretFinding]) -> list[SecretFinding]:
    order = {"high": 0, "medium": 1}
    found.sort(key=lambda f: (order[f.confidence], f.start, -(f.end - f.start)))
    kept: list[SecretFinding] = []
    for f in found:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


# --- credential-file references (FR-013 second clause) --------------------------------------

_SENSITIVE_PATH = re.compile(
    r"""(?x)
    (?<![\w./-])@?(?P<path>
        (?:~|\$HOME|\$\{HOME\}|/(?:Users|home)/[^/\s'"]+)/
            (?:\.aws/(?:credentials|config)
              |\.ssh/id_[A-Za-z0-9_]+(?!\.pub)
              |\.netrc|\.git-credentials
              |\.kube/config|\.docker/config\.json
              |\.config/gcloud/(?:[^\s'"]*/)?(?:credentials[^\s'"]*|application_default_credentials\.json))
      | (?:[\w./-]*/)?\.env(?:\.(?!example\b|sample\b|template\b)[\w-]+)?
      | (?:[\w./-]*/)?application_default_credentials\.json
    )(?![\w.-])""",
)


def scan_sensitive_paths(text: str) -> list[SecretFinding]:
    out = []
    for m in _SENSITIVE_PATH.finditer(text):
        start, end = m.span("path")
        out.append(SecretFinding("sensitive-path", "high", start, end, "sensitive_path"))
    return out


# --- argument walking ---------------------------------------------------------------------


def iter_strings(obj: Any, path: str = "args") -> Iterator[tuple[str, str]]:
    """Yield (json_path, string) for every string leaf, with paths like `args.to` or `args.cc.0`.
    Walks with an explicit stack, so deep nesting is not an error."""
    stack: list[tuple[str, Any]] = [(path, obj)]
    while stack:
        p, cur = stack.pop()
        if isinstance(cur, str):
            yield p, cur
        elif isinstance(cur, dict):
            stack.extend(reversed([(f"{p}.{k}", v) for k, v in cur.items()]))
        elif isinstance(cur, (list, tuple)):
            stack.extend(reversed([(f"{p}.{i}", v) for i, v in enumerate(cur)]))


def string_leaves(obj: Any) -> list[str]:
    """Every string in a JSON value, dict keys included, other scalars as text, without
    recursion: what a tool response can show the model (T136, T137, T143)."""
    out: list[str] = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            out.append(cur)
        elif isinstance(cur, dict):
            out.extend(str(k) for k in cur)
            stack.extend(reversed(list(cur.values())))
        elif isinstance(cur, (list, tuple)):
            stack.extend(reversed(cur))
        elif cur is not None and not isinstance(cur, bool):
            out.append(str(cur))
    return [s for s in out if s]


def map_strings(obj: Any, fn: Callable[[str, str], str], path: str = "args") -> Any:
    """Copy of `obj` with every string leaf replaced by `fn(json_path, string)`."""
    if isinstance(obj, str):
        return fn(path, obj)
    if isinstance(obj, dict):
        return {k: map_strings(v, fn, f"{path}.{k}") for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [map_strings(v, fn, f"{path}.{i}") for i, v in enumerate(obj)]
    return obj


def scan_arguments(
    arguments: dict[str, Any], disabled: frozenset[str] = frozenset()
) -> dict[str, list[SecretFinding]]:
    result: dict[str, list[SecretFinding]] = {}
    for path, value in iter_strings(arguments):
        findings = scan_value(value, disabled)
        if findings:
            result[path] = findings
    return result
