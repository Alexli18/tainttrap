"""Argument provenance: did a value come from the user or from a tool response? (FR-006, FR-007)

Two channels over a per-scope index of untrusted tool output (research R-06):

* k-gram channel: normalized (casefolded, whitespace-collapsed) k-grams, winnowed with window w.
  Any shared run of >= w + k - 1 characters is guaranteed to be found. Query values are also
  checked in URL-decoded and base64-decoded form.
* entity channel: URLs, emails, hosts, IPs, paths and long identifier-like tokens extracted from
  untrusted output, matched exactly (casefolded) with an Aho-Corasick automaton. Catches short
  sinks such as `drop@evil.example`.

This is a best-effort heuristic, not label propagation: paraphrased copies are not caught.
The index lives in daemon memory only, so Python's per-process `hash()` is fine here.

Observed secrets: secret values found in tool output (a key read from `~/.aws/credentials`,
a token in `.env`) are kept per observation, casefolded, in daemon memory only, so a later
argument carrying one in another case, URL-encoded or base64-encoded is still recognised as a
secret (`observed_secrets`). They are dropped with the observation and never logged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus, urlparse

import ahocorasick

from tainttrap.core.rules.secrets import iter_strings, scan_value
from tainttrap.core.types import ArgumentProvenance, Origin

WINDOW = 8
MIN_SECRET_LEN = 8
_WS = re.compile(r"\s+")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

_URL = re.compile(r"""\b(?:https?|ftp|wss?)://[^\s'"<>)\]}]+""", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH = re.compile(r"""(?:~|/)(?:[\w.-]+/)*[\w.-]+""")
_ID_TOKEN = re.compile(r"\b(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{16,}\b")

STOP_ENTITIES = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "www.example.com",
        "github.com",
        "www.github.com",
        "gitlab.com",
        "google.com",
        "www.google.com",
        "pypi.org",
        "npmjs.com",
        "www.npmjs.com",
        "wikipedia.org",
        "en.wikipedia.org",
        "stackoverflow.com",
        "youtube.com",
        "www.youtube.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "docs.python.org",
        "schema.org",
        "w3.org",
        "www.w3.org",
        "/usr/bin",
        "/usr/local/bin",
        "/bin",
        "/tmp",
        "/dev/null",
    }
)
_STOP_FRAGMENTS = ("https://", "http://", "content-type", "application/json")


def normalize(text: str) -> str:
    return _WS.sub(" ", text.casefold()).strip()


def _kgram_hashes(norm: str, k: int) -> list[int]:
    return [hash(norm[i : i + k]) for i in range(len(norm) - k + 1)]


def winnow(norm: str, k: int, w: int = WINDOW) -> set[int]:
    hashes = _kgram_hashes(norm, k)
    if not hashes:
        return set()
    if len(hashes) <= w:
        return {min(hashes)}
    picked = set()
    for i in range(len(hashes) - w + 1):
        picked.add(min(hashes[i : i + w]))
    return picked


def decoded_variants(value: str) -> list[tuple[str, str]]:
    """(kind, text) pairs to check besides the raw value."""
    out: list[tuple[str, str]] = []
    if "%" in value or "+" in value:
        dec = unquote_plus(value)
        if dec != value:
            out.append(("url", dec))
    for m in _B64_RUN.finditer(value):
        run = m.group(0)
        # A run may start with characters that are not part of the encoding (`Z` + base64):
        # try each alignment, not only the first (T140).
        for off in range(4):
            part = run[off:]
            try:
                raw = base64.b64decode(
                    part + "=" * (-len(part) % 4), altchars=b"-_", validate=False
                )
                text = raw.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.9:
                out.append(("base64", text))
                break
    return out


def secret_values(text: str) -> set[str]:
    """Casefolded secret values in a tool response (credential-file paths are not values)."""
    out = set()
    for f in scan_value(text):
        if f.type == "sensitive_path":
            continue
        value = text[f.start : f.end].strip().casefold()
        if len(value) >= MIN_SECRET_LEN:
            out.add(value)
    return out


def _secret_in(value: str, secrets: Iterable[str]) -> str | None:
    """How a known secret appears in `value`: case_folded, url or base64; None if it does not."""
    folded = value.casefold()
    if any(s in folded for s in secrets):
        return "case_folded"
    for kind, text in decoded_variants(value):
        text = text.casefold()
        if any(s in text for s in secrets):
            return kind
    return None


def redact_secrets(value: str, secrets: Iterable[str], placeholder: str) -> str:
    """Replace every form of a known secret in `value` (as `_secret_in` finds them)."""
    secrets = list(secrets)
    for s in secrets:
        value = re.sub(re.escape(s), placeholder, value, flags=re.I)
    if "%" in value or "+" in value:
        dec = unquote_plus(value)
        if any(s in dec.casefold() for s in secrets):
            value = redact_secrets(dec, secrets, placeholder)
    for m in list(_B64_RUN.finditer(value)):
        for kind, text in decoded_variants(m.group(0)):
            if kind == "base64" and any(s in text.casefold() for s in secrets):
                value = value.replace(m.group(0), placeholder)
                break
    return value


def extract_entities(text: str, min_len: int) -> set[str]:
    found: set[str] = set()
    for rx in (_URL, _EMAIL, _IPV4):
        found.update(m.group(0).rstrip(".,;:") for m in rx.finditer(text))
    for m in _URL.finditer(text):
        try:
            host = urlparse(m.group(0)).hostname
        except ValueError:  # e.g. "http://[x": attacker text must not drop the whole output
            continue
        if host:
            found.add(host)
    found.update(m.group(0) for m in _HOST.finditer(text))
    found.update(m.group(0) for m in _PATH.finditer(text) if m.group(0).count("/") >= 2)
    found.update(m.group(0) for m in _ID_TOKEN.finditer(text))
    out = set()
    for e in found:
        e = e.casefold()
        if len(e) >= min_len and e not in STOP_ENTITIES:
            out.add(e)
    return out


class SeenFilter:
    """Bloom filter of destinations evicted from a scope's exact store (T145 follow-up).

    Count eviction lets an attacker push its own address out of the exact store with enough
    invented ones. Every evicted destination is added here, so "first seen in tool output"
    survives eviction; the filter can only err toward untrusted. Sized for CAPACITY entries at
    ERROR_RATE (about 12 MB), allocated on the first eviction only, keyed per scope with a
    random key so its false positives cannot be planned. Past CAPACITY the scope is degraded:
    every destination not provably trusted is treated as untrusted."""

    CAPACITY = 10_000_000
    ERROR_RATE = 0.01

    def __init__(self) -> None:
        self.m = math.ceil(-self.CAPACITY * math.log(self.ERROR_RATE) / math.log(2) ** 2)
        self.k = max(1, round(self.m / self.CAPACITY * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)
        self.key = os.urandom(16)
        self.count = 0

    def _indexes(self, item: str) -> list[int]:
        d = hashlib.blake2b(item.encode(), key=self.key, digest_size=16).digest()
        h1, h2 = int.from_bytes(d[:8], "big"), int.from_bytes(d[8:], "big") | 1
        return [(h1 + i * h2) % self.m for i in range(self.k)]

    def add(self, item: str) -> None:
        for i in self._indexes(item):
            self.bits[i >> 3] |= 1 << (i & 7)
        self.count += 1

    def __contains__(self, item: str) -> bool:
        return all(self.bits[i >> 3] & (1 << (i & 7)) for i in self._indexes(item))

    @property
    def full(self) -> bool:
        return self.count > self.CAPACITY


@dataclass
class _Observation:
    call_id: str
    fingerprints: set[int]
    entities: set[str]
    tool: str | None = None  # "server.tool" or "tool"; used to look up the source's trust tier
    secrets: frozenset[str] = frozenset()  # casefolded secret values seen in this output


@dataclass
class _Scope:
    observations: OrderedDict[str, _Observation] = field(default_factory=OrderedDict)
    fp_index: dict[int, set[str]] = field(default_factory=dict)
    entity_index: dict[str, set[str]] = field(default_factory=dict)
    automaton: Any = None
    derived_files: set[str] = field(default_factory=set)  # written from sensitive files (taint.py)
    # First appearance wins: text the agent already used in a trusted argument (k-gram hashes,
    # entities) is not made untrusted by showing up again in tool output later.
    # Order is the order of checks: `seq` counts checked calls, `call_seq` maps a call id to its
    # check, and each trusted fragment keeps the check at which it was first used.
    seq: int = 0
    call_seq: dict[str, int] = field(default_factory=dict)
    trusted_fps: dict[int, int] = field(default_factory=dict)
    secrets: OrderedDict[str, None] = field(default_factory=OrderedDict)  # casefolded values
    call_tools: OrderedDict[str, str | None] = field(default_factory=OrderedDict)  # call -> tool
    seen: SeenFilter | None = None  # destinations evicted from entity_index (lazy)
    degraded: bool = False  # `seen` overflowed: unproven destinations count as untrusted
    degraded_reported: bool = False
    trusted_entities: dict[str, int] = field(default_factory=dict)
    dirty: bool = True
    size: int = 0
    last_activity: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class _Hit:
    call_ids: tuple[str, ...]
    kind: str
    length: int


class ProvenanceIndex:
    """Per-scope untrusted-fragment index (data-model UntrustedFragmentIndex)."""

    BYTES_PER_FP = 100  # rough Python overhead per stored fingerprint

    def __init__(
        self,
        k: int = 24,
        min_entity_len: int = 6,
        max_bytes: int = 8 * 1024 * 1024,
        ttl_s: float = 24 * 3600,
    ) -> None:
        self.k = k
        self.min_entity_len = min_entity_len
        self.max_bytes = max_bytes
        self.ttl_s = ttl_s
        self._scopes: dict[str, _Scope] = {}

    # -- ingest ---------------------------------------------------------------------------

    def observe(
        self, scope_id: str, call_id: str, chunks: Iterable[str], tool: str | None = None
    ) -> int:
        scope = self._scopes.setdefault(scope_id, _Scope())
        scope.last_activity = time.monotonic()
        fps: set[int] = set()
        ents: set[str] = set()
        secrets: set[str] = set()
        total = 0
        for chunk in chunks:
            if not chunk:
                continue
            total += len(chunk)
            # Encoded content the agent may decode is indexed in decoded form too (T139).
            for text in (chunk, *(t for _, t in decoded_variants(chunk))):
                fps |= winnow(normalize(text), self.k)
                ents |= extract_entities(text, self.min_entity_len)
                secrets |= secret_values(text)
        # Fragments the agent used in a trusted argument no later than the check of the call that
        # produced this output stay trusted. An output observed late (after a later check) is
        # still indexed, because its call was checked before that use. Unknown call: no exemption.
        at = scope.call_seq.get(call_id)
        if at is not None:
            fps = {f for f in fps if scope.trusted_fps.get(f, at + 1) > at}
            ents = {e for e in ents if scope.trusted_entities.get(e, at + 1) > at}
        if call_id in scope.observations:
            self._drop(scope, call_id)
        scope.observations[call_id] = _Observation(call_id, fps, ents, tool, frozenset(secrets))
        # Secrets live in their own store with their own limit: a flood of output that evicts
        # old observations must not make a secret seen earlier unknown again (T144).
        for sv in secrets:
            scope.secrets[sv] = None
            scope.secrets.move_to_end(sv)
        while len(scope.secrets) > self.MAX_SECRETS:
            scope.secrets.popitem(last=False)
        for fp in fps:
            scope.fp_index.setdefault(fp, set()).add(call_id)
        for e in ents:
            scope.entity_index.setdefault(e, set()).add(call_id)
        while len(scope.entity_index) > self.MAX_ENTITIES:
            evicted = next(iter(scope.entity_index))
            scope.entity_index.pop(evicted)
            if scope.seen is None:
                scope.seen = SeenFilter()
            scope.seen.add(evicted)
            if scope.seen.full:
                scope.degraded = True
        scope.call_tools[call_id] = tool
        while len(scope.call_tools) > self.MAX_ENTITIES:
            scope.call_tools.popitem(last=False)
        scope.size += len(fps) * self.BYTES_PER_FP
        scope.dirty = True
        while scope.size > self.max_bytes and len(scope.observations) > 1:
            self._drop(scope, next(iter(scope.observations)))
        return total

    def _drop(self, scope: _Scope, call_id: str) -> None:
        obs = scope.observations.pop(call_id)
        for fp in obs.fingerprints:
            ids = scope.fp_index.get(fp)
            if ids:
                ids.discard(call_id)
                if not ids:
                    del scope.fp_index[fp]
        # Destinations (hosts, URLs, addresses, paths) are kept: output volume, which the
        # attacker controls, must not turn an address first seen in tool output into one the
        # agent seems to have written. Only the full text (k-grams) is evicted (T145).
        scope.size -= len(obs.fingerprints) * self.BYTES_PER_FP
        scope.dirty = True

    def source_tools(self, scope_ids: Iterable[str], call_ids: Iterable[str]) -> set[str | None]:
        """The tools whose output the matched fragments came from (None = unknown)."""
        out: set[str | None] = set()
        wanted = set(call_ids)
        for sid in scope_ids:
            scope = self._scopes.get(sid)
            if scope is None:
                continue
            for cid in wanted:
                if cid in scope.observations:
                    out.add(scope.observations[cid].tool)
                elif cid in scope.call_tools:
                    out.add(scope.call_tools[cid])
        return out

    def observed_secrets(
        self, scope_ids: Iterable[str], arguments: dict[str, Any]
    ) -> tuple[dict[str, str], set[str]]:
        """({arg path: match kind}, the secret values) for arguments that carry a secret seen
        earlier in tool output, in any case or URL/base64 encoding."""
        known: set[str] = set()
        for sid in scope_ids:
            scope = self._scopes.get(sid)
            if scope is not None:
                known |= set(scope.secrets)
        if not known:
            return {}, set()
        hits = {}
        for path, value in iter_strings(arguments):
            kind = _secret_in(value, known)
            if kind:
                hits[path] = kind
        return hits, known

    MAX_ENTITIES = 100_000  # destinations per scope, evicted by count only (oldest first)
    MAX_SECRETS = 10_000  # per scope; the oldest go first, independent of output volume
    MAX_TRUSTED_FPS = 500_000  # per scope; past it nothing more is exempted (fails toward asking)
    MAX_CALLS = 100_000  # call ids remembered per scope for ordering

    def note_check(self, scope_ids: Iterable[str], call_id: str) -> None:
        """Record that `call_id` is being checked now (the order first appearance uses)."""
        for sid in scope_ids:
            scope = self._scopes.setdefault(sid, _Scope())
            scope.seq += 1
            if len(scope.call_seq) >= self.MAX_CALLS:
                scope.call_seq.pop(next(iter(scope.call_seq)))
            scope.call_seq.setdefault(call_id, scope.seq)

    def remember_trusted(
        self, scope_ids: Iterable[str], call_id: str, values: Iterable[str]
    ) -> None:
        """Record argument values of an allowed call that were not untrusted, so a later echo in
        tool output (a printed command, a file the agent wrote and reads back) does not turn
        them untrusted. A value that first appeared in tool output is labelled untrusted and
        never reaches here, so the agent cannot launder an outsider's text by repeating it."""
        fps: set[int] = set()
        ents: set[str] = set()
        for v in values:
            fps.update(_kgram_hashes(normalize(v), self.k))
            ents |= extract_entities(v, self.min_entity_len)
        if not fps and not ents:
            return
        for sid in scope_ids:
            scope = self._scopes.setdefault(sid, _Scope())
            at = scope.call_seq.get(call_id)
            if at is None or len(scope.trusted_fps) + len(fps) > self.MAX_TRUSTED_FPS:
                continue
            for f in fps:
                scope.trusted_fps.setdefault(f, at)
            for e in ents:
                scope.trusted_entities.setdefault(e, at)

    def add_derived(self, scope_ids: Iterable[str], paths: Iterable[str]) -> None:
        paths = set(paths)
        for sid in scope_ids:
            self._scopes.setdefault(sid, _Scope()).derived_files |= paths

    def derived_files(self, scope_ids: Iterable[str]) -> set[str]:
        out: set[str] = set()
        for sid in scope_ids:
            scope = self._scopes.get(sid)
            if scope is not None:
                out |= scope.derived_files
        return out

    def evict_expired(self) -> None:
        now = time.monotonic()
        for sid in [s for s, sc in self._scopes.items() if now - sc.last_activity > self.ttl_s]:
            del self._scopes[sid]

    def drop_scope(self, scope_id: str) -> None:
        self._scopes.pop(scope_id, None)

    # -- query ----------------------------------------------------------------------------

    def _automaton(self, scope: _Scope) -> Any:
        if scope.dirty:
            if scope.entity_index:
                a = ahocorasick.Automaton()
                for e in scope.entity_index:
                    a.add_word(e, e)
                a.make_automaton()
                scope.automaton = a
            else:
                scope.automaton = None
            scope.dirty = False
        return scope.automaton

    def _kgram_hits(
        self, scopes: list[_Scope], norm: str, exclude: set[int]
    ) -> tuple[set[str], int]:
        # Only winnowed fingerprints are stored, so hits are sparse inside a shared run.
        # Hits at most WINDOW positions apart belong to the same run.
        ids: set[str] = set()
        positions: list[int] = []
        for i, h in enumerate(_kgram_hashes(norm, self.k)):
            if h in exclude:
                continue
            for sc in scopes:
                hit = sc.fp_index.get(h)
                if hit:
                    ids |= hit
                    positions.append(i)
                    break
        best = 0
        start = prev = None
        for p in positions:
            if start is None or prev is None or p - prev > WINDOW:
                start = p
            prev = p
            best = max(best, p - start + self.k)
        return ids, best

    def _entity_hits(
        self, scopes: list[_Scope], folded: str, task_folded: str
    ) -> tuple[set[str], int]:
        ids: set[str] = set()
        best = 0
        for sc in scopes:
            a = self._automaton(sc)
            if a is None:
                continue
            for end, ent in a.iter(folded):
                start = end - len(ent) + 1
                before = folded[start - 1] if start > 0 else " "
                after = folded[end + 1] if end + 1 < len(folded) else " "
                if before.isalnum() or after.isalnum():
                    continue  # not a whole-token match
                if ent in task_folded:
                    continue
                ids |= sc.entity_index[ent]
                best = max(best, len(ent))
        return ids, best

    def _check_value(
        self, scopes: list[_Scope], value: str, task_norm: str, task_fps: set[int]
    ) -> _Hit | None:
        candidates = [("exact", value), *decoded_variants(value)]
        for kind, text in candidates:
            folded = text.casefold()
            norm = normalize(text)
            if any(f == norm for f in _STOP_FRAGMENTS):
                continue
            ids, length = self._kgram_hits(scopes, norm, task_fps)
            if ids:
                if kind == "exact":
                    kind = "exact" if length >= 0.9 * len(norm) else "substring"
                return _Hit(tuple(sorted(ids)), kind, length)
            ids, length = self._entity_hits(scopes, folded, task_norm)
            if ids:
                return _Hit(tuple(sorted(ids)), "entity" if kind == "exact" else kind, length)
            hit = self._evicted_hit(scopes, text, task_norm)
            if hit:
                return hit
        return None

    def _evicted_hit(self, scopes: list[_Scope], text: str, task_norm: str) -> _Hit | None:
        """A destination no longer in the exact store but in the evicted-destinations filter:
        untrusted, with its details gone (`details_evicted`)."""
        if not any(sc.seen for sc in scopes):
            return None
        for e in extract_entities(text, self.min_entity_len):
            if e in task_norm:
                continue
            for sc in scopes:
                if sc.seen is not None and e in sc.seen and e not in sc.trusted_entities:
                    return _Hit((), "details_evicted", len(e))
        return None

    def mark_degraded(self, scope_id: str) -> bool:
        """Degrade a scope (e.g. a session whose earlier state this process never had). True if
        it was not degraded before."""
        scope = self._scopes.setdefault(scope_id, _Scope())
        if scope.degraded:
            return False
        scope.degraded = scope.degraded_reported = True
        return True

    def degraded(self, scope_ids: Iterable[str]) -> bool:
        return any(sc.degraded for sid in scope_ids if (sc := self._scopes.get(sid)))

    def newly_degraded(self, scope_ids: Iterable[str]) -> list[str]:
        """Scopes that became degraded since last asked (for a one-time log entry)."""
        out = []
        for sid in scope_ids:
            sc = self._scopes.get(sid)
            if sc is not None and sc.degraded and not sc.degraded_reported:
                sc.degraded_reported = True
                out.append(sid)
        return out

    def proven_trusted_entity(self, scope_ids: Iterable[str], entity: str) -> bool:
        return any(
            entity in sc.trusted_entities for sid in scope_ids if (sc := self._scopes.get(sid))
        )

    def label(
        self, scope_ids: Iterable[str], task_texts: Iterable[str], arguments: dict[str, Any]
    ) -> list[ArgumentProvenance]:
        scopes = [self._scopes[s] for s in scope_ids if s in self._scopes]
        task_norm = normalize(" ".join(t for t in task_texts if t))
        task_hashes = set(_kgram_hashes(task_norm, self.k))
        task_entities = extract_entities(task_norm, self.min_entity_len)
        out: list[ArgumentProvenance] = []
        for path, value in iter_strings(arguments):
            hit = self._check_value(scopes, value, task_norm, task_hashes) if scopes else None
            if hit:
                out.append(
                    ArgumentProvenance(
                        path=path,
                        origin=Origin.UNTRUSTED,
                        matched_call_ids=hit.call_ids,
                        match_kind=hit.kind,
                        match_len=hit.length,
                    )
                )
                continue
            norm = normalize(value)
            if norm and (
                norm in task_norm
                or any(e in norm for e in task_entities)
                or (len(norm) >= self.k and set(_kgram_hashes(norm, self.k)) & task_hashes)
            ):
                out.append(ArgumentProvenance(path=path, origin=Origin.USER))
            elif len(norm) < self.min_entity_len:
                out.append(ArgumentProvenance(path=path, origin=Origin.LITERAL))
            else:
                out.append(ArgumentProvenance(path=path, origin=Origin.DERIVED))
        return out
