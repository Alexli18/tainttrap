"""Registrable domains (eTLD+1) from the vendored Public Suffix List, and "did the user name this
host?" for the upload rule.

A host counts as named by the task only through its registrable domain, never through a word in
its name: "GitHub" must not vouch for `github-uploads.evil.example`, `github.xyz` or
`attacker.github.io` (github.io is a public suffix, so anyone owns a subdomain there). A brand
word in the task maps to a short curated list of registrable domains; anything else must be
named as a domain in the task or allowed in the policy.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib.resources import files

# Brand word in the task -> registrable domains it vouches for. Only services whose upload hosts
# live under domains the vendor owns outright (not shared hosting such as github.io or S3).
BRANDS: dict[str, frozenset[str]] = {
    "github": frozenset({"github.com"}),  # githubusercontent.com is a public suffix itself
    "gitlab": frozenset({"gitlab.com"}),
    "bitbucket": frozenset({"bitbucket.org"}),
    "npm": frozenset({"npmjs.org", "npmjs.com"}),
    "pypi": frozenset({"pypi.org"}),
    "docker hub": frozenset({"docker.io", "docker.com"}),
}
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_HOSTLIKE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*")


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    text = files("tainttrap.data").joinpath("psl/suffixes.txt").read_text("utf-8")
    exact: set[str] = set()
    wild: set[str] = set()
    exc: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            exc.add(line[1:])
        elif line.startswith("*."):
            wild.add(line[2:])
        else:
            exact.add(line)
    return frozenset(exact), frozenset(wild), frozenset(exc)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def public_suffix(host: str) -> str:
    """The longest matching public suffix (PSL algorithm; the default rule is `*`)."""
    exact, wild, exc = _rules()
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in exc:
            return ".".join(labels[i + 1 :])
        if cand in exact or (i + 1 < len(labels) and ".".join(labels[i + 1 :]) in wild):
            return cand
    return labels[-1]


def registrable_domain(host: str) -> str | None:
    """eTLD+1, the host itself for an IP address, None for a bare public suffix."""
    host = host.lower().rstrip(".")
    if _is_ip(host):
        return host
    suffix = public_suffix(host)
    if host == suffix:
        return None
    head = host[: -len(suffix) - 1].rsplit(".", 1)[-1]
    return f"{head}.{suffix}"


def named_domains(task: str | None) -> set[str]:
    """Registrable domains the task names: written as domains, URLs, emails or brand words."""
    if not task:
        return set()
    out: set[str] = set()
    for m in _HOSTLIKE.finditer(task):
        reg = registrable_domain(m.group(0).split("@")[-1])
        if reg:
            out.add(reg)
    t = task.casefold()
    for word, domains in BRANDS.items():
        if re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", t):
            out |= domains
    return out


def host_known(host: str, task: str | None, allow: Iterable[str]) -> bool:
    """Loopback, a policy-allowed domain (and its subdomains), or a host whose registrable
    domain the task names."""
    host = host.lower().rstrip(".")
    if host in LOCAL_HOSTS or host.endswith(".localhost"):
        return True
    for d in allow:
        d = d.lower().removeprefix("*.").rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    reg = registrable_domain(host)
    return reg is not None and reg in named_domains(task)
