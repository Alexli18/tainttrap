"""Self-protection (spec FR-032, contracts/claude-code-hook.md "Self-protection").

Blocks agent tool calls that write, move or delete TaintTrap's or Claude Code's config,
that stop TaintTrap, or that run any state-changing `tainttrap` command. Reading is allowed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from tainttrap.core import paths
from tainttrap.core.policy import Policy
from tainttrap.core.rules.base import CallContext, split_shell
from tainttrap.core.types import RuleResult

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file"})
PATH_ARGS = ("file_path", "path", "notebook_path", "target", "destination")

READ_ONLY_SHELL = frozenset(
    {
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "grep",
        "rg",
        "ls",
        "stat",
        "wc",
        "jq",
        "diff",
        "file",
        "find",
        "echo",
        "test",
        "[",
        "sha256sum",
        "shasum",
        "md5",
        "md5sum",
    }
)
READ_ONLY_SUBCOMMANDS = (
    ("report",),
    ("log",),
    ("status",),
    ("daemon", "status"),
    ("policy", "show"),
    ("policy", "validate"),
    ("registry", "list"),
    ("model", "info"),
    ("recipients", "list"),
    ("doctor",),
    ("--help",),
    ("--version",),
)
_SEGMENT_SPLIT = re.compile(r"\s*(?:\|\||&&|;|\||\n)\s*")
# Wrapped or indirect invocations that the argv parser cannot see through: `script -q /dev/null
# tainttrap approve`, `pty.spawn(["tainttrap", "approve", ...])`, `bash -c '...'`, driving the
# package from Python, or talking to the admin socket directly. Matched on the raw command.
_WRAPPED_COMMAND = re.compile(
    r"""tainttrap(?:-hook)?['"]?\s*[,\s]\s*['"]?"""
    r"(?:approve|deny|approvals|daemon|policy|registry|flag|install|uninstall|model|run|init|recipients|"
    r"pre-tool|post-tool|user-prompt|session-end)\b"
)
_PACKAGE_USE = re.compile(
    r"(?:-m\s+|\bimport\s+|\bfrom\s+)tainttrap\b|\badmin\.sock\b|\bcheck\.sock\b"
)
_READ_ONLY_WRAPPED = re.compile(
    r"""tainttrap['"]?\s*[,\s]\s*['"]?(?:report|log|status|doctor|--help|--version)\b"""
    r"""|tainttrap['"]?\s*[,\s]\s*['"]?(?:daemon|policy|registry|model|recipients)['"]?\s*[,\s]\s*['"]?"""
    r"(?:status|show|validate|list|info)\b"
)

# Text that only appears when a command touches Claude Code's or TaintTrap's own settings or
# switches hooks off: caught even inside interpreter one-liners and after `cd`.
_SETTINGS_TEXT = re.compile(
    r"\.claude[/\\]+settings(?:\.local)?\.json|managed-settings\.json|\bhook\.json\b|"
    r"approved_recipients\.json|"
    # the switches only when assigned (`"disableAllHooks": true`, `.disableAllHooks=true`), so
    # commit messages, docs and greps that merely mention them are not blocked
    r"""["'.]?(?:disableAllHooks|allowManagedHooksOnly|disableBypassPermissionsMode)["']?\s*[:=]"""
)
# A JSON key that turns hooks off. Only checked for JSON targets: anywhere else the words are
# just text (docs, tests), and moving such a file into .claude/ is caught by the path rule.
_HOOK_SWITCHES = re.compile(r"""["'](?:disableAllHooks|allowManagedHooksOnly)["']\s*:""")
_JSON_SUFFIXES = (".json", ".jsonc", ".json5")
_READ_ONLY_GIT = frozenset({"diff", "log", "show", "status", "blame"})
CONTENT_ARGS = ("content", "new_string", "new_source", "edits")

_STOP_PROCESS = re.compile(
    r"\b(?:kill|pkill|killall|launchctl|systemctl)\b[^;&|]*\btainttrap", re.I
)
_REDIRECT = re.compile(r"(?<![<>&\d])>{1,2}(?!&)|\btee\b|\bsed\s+-i|\bdd\b")

MANAGED_SETTINGS = (
    Path("/Library/Application Support/ClaudeCode"),
    Path("/etc/claude-code"),
    Path("/Library/Application Support/TaintTrap"),
    Path("/etc/tainttrap"),
)


def protected_roots() -> list[Path]:
    home = Path.home()
    roots = [
        paths.config_dir(),
        paths.home_dir(),
        paths.runtime_dir(),
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        *MANAGED_SETTINGS,
    ]
    return [Path(os.path.realpath(r)) for r in roots]


def _expand(p: str, cwd: str | None) -> Path:
    p = os.path.expandvars(os.path.expanduser(p.strip("'\"")))
    path = Path(p)
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    return Path(os.path.realpath(path))


def _is_protected(p: Path, roots: list[Path]) -> bool:
    if p.name.startswith("settings") and p.suffix == ".json" and p.parent.name == ".claude":
        return True
    return any(p == r or r in p.parents for r in roots)


def _tainttrap_argv(tokens: list[str]) -> list[str] | None:
    """Return the argv after the `tainttrap` program name, or None if not an tainttrap call."""
    i = 0
    while i < len(tokens) and ("=" in tokens[i] and not tokens[i].startswith("-")):
        i += 1  # VAR=value prefixes
    if i < len(tokens) and tokens[i] in ("env", "sudo", "exec", "nohup", "time"):
        return _tainttrap_argv(tokens[i + 1 :])
    if i < len(tokens) - 1 and tokens[i] == "uv" and tokens[i + 1] == "run":
        return _tainttrap_argv(tokens[i + 2 :])
    if i >= len(tokens):
        return None
    prog = os.path.basename(tokens[i])
    if prog in ("tainttrap", "tainttrap-hook"):
        return [prog, *tokens[i + 1 :]]
    if prog.startswith("python") and tokens[i + 1 : i + 3][:1] == ["-m"] and len(tokens) > i + 2:
        mod = tokens[i + 2]
        if mod == "tainttrap" or mod.startswith("tainttrap."):
            return ["tainttrap", *tokens[i + 3 :]] if mod == "tainttrap" else [mod, "*"]
    return None


def _state_changing_tainttrap(argv: list[str]) -> bool:
    if argv[0] != "tainttrap":
        return True  # tainttrap-hook or internal modules run directly by the agent
    args = [a for a in argv[1:] if a != "--json"]
    return not any(tuple(args[: len(sub)]) == sub for sub in READ_ONLY_SUBCOMMANDS)


class SelfProtect:
    rule_id = "self_protect"

    def evaluate(self, ctx: CallContext, policy: Policy) -> RuleResult | None:
        cwd = ctx.extra.get("cwd")
        roots = protected_roots()
        if ctx.tool_name in WRITE_TOOLS:
            for key in PATH_ARGS:
                v = ctx.arguments.get(key)
                if isinstance(v, str) and _is_protected(_expand(v, cwd), roots):
                    return self._block("self_protect.config_path", f"write to protected path {v}")
            target = next((str(ctx.arguments[k]) for k in PATH_ARGS if ctx.arguments.get(k)), "")
            written = " ".join(str(ctx.arguments.get(k, "")) for k in CONTENT_ARGS)
            if target.lower().endswith(_JSON_SUFFIXES) and _HOOK_SWITCHES.search(written):
                return self._block(
                    "self_protect.hook_switch", "writes a setting that turns hooks off"
                )
        cmd = ctx.shell_command()
        if not cmd:
            return None
        if _STOP_PROCESS.search(cmd):
            return self._block("self_protect.stop_process", "stops the TaintTrap process")
        if _PACKAGE_USE.search(cmd):
            return self._block("self_protect.command", "drives TaintTrap internals or its sockets")
        starts = [m.start() for m in _WRAPPED_COMMAND.finditer(cmd)]
        if any(not _READ_ONLY_WRAPPED.match(cmd, i) for i in starts):
            return self._block(
                "self_protect.command", f"state-changing TaintTrap command: {cmd[:80]}"
            )
        segments = [split_shell(seg) for seg in _SEGMENT_SPLIT.split(cmd)]
        writes = not all(
            _read_only(t, seg)
            for t, seg in zip(segments, _SEGMENT_SPLIT.split(cmd), strict=True)
            if t
        )
        if writes and _SETTINGS_TEXT.search(cmd):
            return self._block(
                "self_protect.config_path", "modifies Claude Code or TaintTrap settings"
            )
        here = cwd
        for segment in _SEGMENT_SPLIT.split(cmd):
            tokens = split_shell(segment)
            if not tokens:
                continue
            if os.path.basename(tokens[0]) == "cd":
                target = tokens[1] if len(tokens) > 1 else "~"
                here = str(_expand(target, here))
                continue
            argv = _tainttrap_argv(tokens)
            if argv is not None and _state_changing_tainttrap(argv):
                return self._block(
                    "self_protect.command", f"state-changing TaintTrap command: {segment[:80]}"
                )
            touched = [
                t
                for t in tokens[1:]
                if ("/" in t or "." in t or t.startswith(("~", "$")))
                and _is_protected(_expand(t.lstrip(">"), here), roots)
            ]
            if touched:
                if not _read_only(tokens, segment):
                    return self._block(
                        "self_protect.config_path", f"modifies protected path {touched[0]}"
                    )
        return None

    @staticmethod
    def _block(rule_id: str, evidence: str) -> RuleResult:
        return RuleResult(
            rule_id=rule_id,
            verdict="block",
            final=True,
            evidence=evidence,
            severity="critical",
            reason_codes=("self_protect",),
        )


def _read_only(tokens: list[str], segment: str) -> bool:
    if _REDIRECT.search(segment):
        return False
    prog = os.path.basename(tokens[0])
    if prog == "git":
        return len(tokens) > 1 and tokens[1] in _READ_ONLY_GIT
    return prog in READ_ONLY_SHELL
