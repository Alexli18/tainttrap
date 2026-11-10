"""Deterministic rules that run before the model (FR-012..FR-015, FR-021, FR-032)."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from tainttrap.core.domains import host_known
from tainttrap.core.policy import Policy
from tainttrap.core.rules.secrets import SecretFinding
from tainttrap.core.types import ArgumentProvenance, Origin, Outcome, RiskClass, RuleResult

ADDRESSEE_KEYS = frozenset(
    {"to", "cc", "bcc", "recipient", "recipients", "channel", "webhook", "webhook_url", "email"}
)
DESTINATION_KEYS = ADDRESSEE_KEYS | {"url", "uri", "endpoint", "host", "address", "destination"}
BODY_KEYS = frozenset(
    {"body", "data", "json", "payload", "content", "files", "attachments", "form"}
)
SHELL_ARGS = ("command", "cmd", "script")

_CURL_DATA_FLAGS = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode|-ascii)?|-F|--form(?:-string)?|-T|"
    r"--upload-file|--json)(?:[\s=]|$)|(?:^|\s)-X\s*(?:POST|PUT|PATCH)\b|--request\s+(?:POST|PUT|PATCH)\b"
    # combined short flags such as `-sT file`, `-fsd @x`
    r"|(?:^|\s)-[a-zA-Z]*[dFT](?:\s|$)"
)
_WGET_POST = re.compile(r"--post-(?:data|file)\b|--method[= ](?:POST|PUT|PATCH)\b")
_PUSH_COMMANDS = re.compile(
    r"(?:^|[;&|(]\s*)(?:sudo\s+)?(?:scp|rsync|nc|ncat|sendmail|mail|mailx|sftp|ftp)\b"
)
_FETCH_COMMANDS = re.compile(r"(?:^|[;&|(]\s*)(?:sudo\s+)?(curl|wget)\b(?P<rest>[^;&|]*)")
# Anything in a command line that can open a connection (for "is a secret leaving?").
_NETWORK_HINTS = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|telnet|ssh|scp|sftp|ftp|rsync|sendmail|mailx?|"
    r"urllib|urlopen|requests\.|httpx|http\.client|aiohttp|socket\.|fetch\(|Net::HTTP|"
    r"Invoke-WebRequest|iwr)\b|/dev/(?:tcp|udp)/"
)

# A local file sent out by a shell command (curl -T/-F x=@f/--data @f, wget --post-file, scp,
# rsync to a remote, nc < file).
_FILE_UPLOAD = re.compile(
    r"(?:^|\s)(?:-[a-zA-Z]*T|--upload-file)[\s=]+\S"
    r"|(?:^|\s)(?:-F|--form)\s+\S*=@\S"
    r"|(?:^|\s)(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|--json)[\s=]+@\S"
    r"|--post-file[\s=]+\S"
    r"|(?:^|[;&|(]\s*)(?:sudo\s+)?(?:scp|rsync|sftp)\b[^;&|]*\s(?:[\w.-]+@)?[\w.-]+:"
    r"|(?:^|[;&|(]\s*)(?:nc|ncat|socat|telnet)\b[^;&|]*<\s*\S"
)
_URL_HOST = re.compile(r"(?i)\b(?:https?|ftp|sftp|scp)://(?:[^@/\s'\"]+@)?([\w.-]+)")
_REMOTE_HOST = re.compile(r"\s(?:[\w.-]+@)?([A-Za-z0-9][\w-]*(?:\.[\w-]+)+):")
_NC_HOST = re.compile(r"\b(?:nc|ncat|telnet)\s+(?:-\S+\s+)*([\w.-]+)\s+\d+")


def command_hosts(cmd: str) -> set[str]:
    hosts = {m.group(1).lower().rstrip(".") for m in _URL_HOST.finditer(cmd)}
    hosts |= {m.group(1).lower() for m in _REMOTE_HOST.finditer(" " + cmd)}
    hosts |= {m.group(1).lower() for m in _NC_HOST.finditer(cmd)}
    return hosts


@dataclass
class CallContext:
    tool_name: str
    server: str | None
    arguments: dict[str, Any]
    risk_class: RiskClass
    provenance: Sequence[ArgumentProvenance]
    secrets: dict[str, list[SecretFinding]]
    task_text: str | None
    extra: dict[str, Any] = field(default_factory=dict)

    def origin(self, path: str) -> Origin | None:
        for p in self.provenance:
            if p.path == path:
                return p.origin
        return None

    def untrusted_paths(self) -> list[str]:
        return [p.path for p in self.provenance if p.origin is Origin.UNTRUSTED]

    def shell_command(self) -> str | None:
        """The shell command, plus the expanded task-runner recipe when there is one."""
        for key in SHELL_ARGS:
            v = self.arguments.get(key)
            if isinstance(v, str):
                expanded = self.arguments.get("expanded_command")
                return f"{v} ; {expanded}" if isinstance(expanded, str) else v
        return None


class Rule(Protocol):
    rule_id: str

    def evaluate(self, ctx: CallContext, policy: Policy) -> RuleResult | None: ...


def _key(path: str) -> str:
    """`args.to.0` -> `to`; `args.headers.x` -> `x`."""
    parts = [p for p in path.split(".")[1:] if not p.isdigit()]
    return parts[-1].lower() if parts else ""


def data_goes_out(ctx: CallContext) -> bool:
    """Spec FR-021: an addressee, a request body, POST/PUT/PATCH, an upload, `curl` data flags,
    or a secret in the arguments. A plain GET of a URL is not data going out."""
    if ctx.secrets:
        return True
    if any(_key(p.path) in ADDRESSEE_KEYS for p in ctx.provenance):
        return True
    method = str(ctx.arguments.get("method", "")).upper()
    if method in ("POST", "PUT", "PATCH"):
        return True
    if any(k.lower() in BODY_KEYS and v for k, v in ctx.arguments.items()):
        return True
    cmd = ctx.shell_command()
    if cmd:
        if _PUSH_COMMANDS.search(cmd):
            return True
        for m in _FETCH_COMMANDS.finditer(cmd):
            rest = m.group("rest")
            if m.group(1) == "curl" and _CURL_DATA_FLAGS.search(rest):
                return True
            if m.group(1) == "wget" and _WGET_POST.search(rest):
                return True
    return False


def untrusted_destination(ctx: CallContext) -> list[str]:
    out = []
    for p in ctx.provenance:
        if p.origin is not Origin.UNTRUSTED:
            continue
        k = _key(p.path)
        if k in DESTINATION_KEYS or k in SHELL_ARGS:
            out.append(p.path)
    return out


class SecretToExternal:
    """High-confidence secret (incl. a credential-file reference) leaving the machine."""

    rule_id = "secret.to_external"

    def evaluate(self, ctx: CallContext, policy: Policy) -> RuleResult | None:
        cfg = policy.rules.secrets
        if not cfg.enabled or not ctx.secrets:
            return None
        findings = [f for fs in ctx.secrets.values() for f in fs]
        high = [f for f in findings if f.confidence == "high"]
        dests = untrusted_destination(ctx)
        cmd = ctx.shell_command()
        if cmd is not None and not _NETWORK_HINTS.search(cmd):
            # A shell command carrying tool output is not a destination unless it can send.
            dests = [d for d in dests if _key(d) not in SHELL_ARGS]
        external = ctx.risk_class is RiskClass.EXTERNAL_COMMUNICATION or bool(dests)
        types = sorted({f.type for f in findings})
        if high and external:
            return RuleResult(
                rule_id=self.rule_id,
                verdict=cfg.high_confidence_action.value,
                final=cfg.high_confidence_action is not Outcome.ALLOW,
                evidence=f"secret types: {', '.join(types)} in {', '.join(sorted(ctx.secrets))}",
                severity="critical",
                reason_codes=("secret_in_args",),
            )
        if findings and external:
            return RuleResult(
                rule_id="secret.medium_confidence",
                verdict=cfg.medium_confidence_action.value,
                final=False,
                evidence=f"possible secret: {', '.join(types)}",
                severity="warn",
                reason_codes=("possible_secret_in_args",),
            )
        return None


class LocalFileUpload:
    """A shell command uploads a local file to a host the user never named (two-step leak:
    the file may be a copy of a secret that no rule recognises). Not final: it turns an allow
    into a question and never loosens a block."""

    rule_id = "upload.unknown_host"

    def evaluate(self, ctx: CallContext, policy: Policy) -> RuleResult | None:
        cmd = ctx.shell_command()
        if not cmd or not _FILE_UPLOAD.search(cmd):
            return None
        unknown = sorted(
            h
            for h in command_hosts(cmd)
            if not host_known(h, ctx.task_text, policy.rules.domains.allow)
        )
        if not unknown:
            return None
        return RuleResult(
            rule_id=self.rule_id,
            verdict="ask",
            final=False,
            evidence=f"file upload to {', '.join(unknown)}",
            severity="warn",
            reason_codes=("upload_unknown_host",),
        )


def addressee_values(arguments: dict[str, Any]) -> list[str]:
    """Casefolded recipients (to/cc/bcc/... values, including list items)."""
    out: list[str] = []
    for key, value in arguments.items():
        if key.lower() not in ADDRESSEE_KEYS:
            continue
        items = value if isinstance(value, (list, tuple)) else [value]
        for v in items:
            if isinstance(v, str):
                out += [part.strip().casefold() for part in v.split(",") if part.strip()]
    return out


class UntrustedRecipientExternal:
    """Data goes out to a destination that came from tool output (spec FR-021).

    Recipients the human already approved never trigger it. A recipient that came only from a
    first-party directory (the user's own address book) is asked about instead of blocked:
    recipients legitimately come from such tools, and a poisoned entry still needs a human "yes".
    """

    rule_id = "recipient.untrusted_external"

    def evaluate(self, ctx: CallContext, policy: Policy) -> RuleResult | None:
        if ctx.risk_class is not RiskClass.EXTERNAL_COMMUNICATION:
            return None
        dests = untrusted_destination(ctx)
        if not dests or not data_goes_out(ctx):
            return None
        addressee_only = all(_key(d) in ADDRESSEE_KEYS for d in dests)
        recipients = ctx.extra.get("recipients") or []
        known = ctx.extra.get("known_recipients") or set()
        if addressee_only and recipients and all(r in known for r in recipients):
            return None
        if addressee_only and ctx.extra.get("recipient_trust") == "first_party" and not ctx.secrets:
            return RuleResult(
                rule_id="recipient.from_directory",
                verdict="ask",
                final=True,
                evidence=f"recipient from the address book in {', '.join(dests)}",
                severity="warn",
                reason_codes=("recipient_from_directory",),
            )
        action = policy.rules.untrusted_recipient_external
        return RuleResult(
            rule_id=self.rule_id,
            verdict=action.value,
            final=action is not Outcome.ALLOW,
            evidence=f"untrusted destination in {', '.join(dests)}",
            severity="critical",
            reason_codes=("untrusted_recipient",),
        )


def split_shell(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()
