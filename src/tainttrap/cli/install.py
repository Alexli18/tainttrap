"""`tainttrap install|uninstall claude-code` (T055, contracts/claude-code-hook.md)."""

from __future__ import annotations

import difflib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from tainttrap.core import paths
from tainttrap.core.policy import load_policy

MARKER = "tainttrap-hook"
EVENTS: dict[str, tuple[str, str | None, int]] = {
    # event: (subcommand, matcher, timeout seconds)
    "SessionStart": ("session-start", None, 10),  # sessions the daemon saw start (T155)
    "UserPromptSubmit": ("user-prompt", None, 10),
    "PreToolUse": ("pre-tool", ".*", 30),
    "PostToolUse": ("post-tool", ".*", 10),
    "PostToolUseFailure": ("post-tool-failure", ".*", 10),  # failed calls' output (T142)
    "SessionEnd": ("session-end", None, 2),
    "ConfigChange": ("config-change", None, 10),
}
MANAGED_SETTINGS = {
    "darwin": Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    "linux": Path("/etc/claude-code/managed-settings.json"),
}


def hook_binary() -> str:
    candidate = Path(sys.executable).parent / MARKER
    if candidate.exists():
        return str(candidate)
    found = shutil.which(MARKER)
    if not found:
        raise click.ClickException(f"{MARKER} not found next to {sys.executable} or on PATH")
    return found


def settings_path(scope: str) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    if scope == "managed":
        return MANAGED_SETTINGS["darwin" if sys.platform == "darwin" else "linux"]
    raise click.ClickException(f"unknown scope {scope}")


def _is_ours(handler: dict[str, Any]) -> bool:
    return MARKER in str(handler.get("command", ""))


def remove_ours(settings: dict[str, Any]) -> dict[str, Any]:
    hooks = settings.get("hooks", {})
    for event in list(hooks):
        groups = []
        for group in hooks[event]:
            kept = [h for h in group.get("hooks", []) if not _is_ours(h)]
            if kept:
                groups.append({**group, "hooks": kept})
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    return settings


APPROVAL_MARGIN_S = 30  # the hook must outlive the longest human approval wait


def add_ours(settings: dict[str, Any], binary: str, human_timeout_s: int) -> dict[str, Any]:
    settings = remove_ours(settings)
    hooks = settings.setdefault("hooks", {})
    for event, (sub, matcher, timeout) in EVENTS.items():
        if event == "PreToolUse":
            timeout = max(timeout, human_timeout_s + APPROVAL_MARGIN_S)
        handler: dict[str, Any] = {
            "type": "command",
            "command": f"{binary} {sub}",
            "timeout": timeout,
        }
        if event == "PreToolUse":
            handler["onFailure"] = "block"  # a crashed or timed-out hook never lets the call run
        group: dict[str, Any] = {"hooks": [handler]}
        if matcher:
            group = {"matcher": matcher, **group}
        hooks.setdefault(event, []).append(group)
    return settings


def _apply(path: Path, new: dict[str, Any], dry_run: bool, yes: bool) -> None:
    old_text = path.read_text() if path.exists() else ""
    new_text = json.dumps(new, indent=2, ensure_ascii=False) + "\n"  # keep the user's text as is
    if old_text == new_text:
        click.echo(f"{path}: already up to date")
        return
    diff = difflib.unified_diff(
        old_text.splitlines(True), new_text.splitlines(True), str(path), str(path) + " (new)"
    )
    click.echo("".join(diff))
    if dry_run:
        return
    if not yes and not click.confirm(f"Write {path}?", default=False):
        raise click.Abort()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(path.name + ".tainttrap.bak")
        if not backup.exists():
            backup.write_text(old_text)
            click.echo(f"backup: {backup}")
    path.write_text(new_text)
    click.echo(f"wrote {path}")


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"{path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise click.ClickException(f"{path}: expected a JSON object")
    return data


@click.group()
def install() -> None:
    """Connect TaintTrap to an agent."""


@click.group()
def uninstall() -> None:
    """Disconnect TaintTrap from an agent (restores the user's own entries)."""


@install.command("claude-code")
@click.option(
    "--scope", type=click.Choice(["user", "project", "managed"]), default="user", show_default=True
)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.option(
    "--disable-bypass",
    is_flag=True,
    help="Also set permissions.disableBypassPermissionsMode (recommended with --scope managed).",
)
def install_claude_code(scope: str, dry_run: bool, yes: bool, disable_bypass: bool) -> None:
    """Add TaintTrap's hooks to Claude Code settings (merged with your own hooks).

    Only `--scope managed` (root-owned, needs sudo) is a guarantee: project/local
    `disableAllHooks` cannot switch managed hooks off, and the agent cannot edit the file.
    """
    path = settings_path(scope)
    policy = load_policy(paths.policy_file())
    settings = add_ours(_load(path), hook_binary(), policy.human.timeout_s)
    if disable_bypass:
        settings.setdefault("permissions", {})["disableBypassPermissionsMode"] = "disable"
    try:
        _apply(path, settings, dry_run, yes)
    except PermissionError as e:
        raise click.ClickException(f"{e}; the managed scope needs sudo") from e
    click.echo("note: re-run after changing human.timeout_s; `tainttrap doctor` checks this")
    if scope != "managed":
        click.echo(
            "note: hooks in user/project settings are a best-effort layer; for a guarantee run "
            "`sudo tainttrap install claude-code --scope managed --disable-bypass`"
        )


@uninstall.command("claude-code")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True)
def uninstall_claude_code(scope: str, dry_run: bool, yes: bool) -> None:
    path = settings_path(scope)
    if not path.exists():
        click.echo(f"{path}: nothing to remove")
        return
    _apply(path, remove_ours(_load(path)), dry_run, yes)


# -- MCP client configs (T074) ---------------------------------------------------------------

MCP_DEFAULT_CONFIG = {
    "claude-code": (Path(".mcp.json"), "mcpServers"),
    "cursor": (Path(".cursor") / "mcp.json", "mcpServers"),
    "vscode": (Path(".vscode") / "mcp.json", "servers"),
}


def tainttrap_binary() -> str:
    candidate = Path(sys.executable).parent / "tainttrap"
    if candidate.exists():
        return str(candidate)
    return shutil.which("tainttrap") or "tainttrap"


def _is_wrapped(entry: dict[str, Any]) -> bool:
    args = entry.get("args") or []
    return (
        str(entry.get("command", "")).endswith("tainttrap") and args[:1] == ["run"] and "--" in args
    )


def wrap_entry(name: str, entry: dict[str, Any], binary: str) -> dict[str, Any] | None:
    """Rewrite a stdio server entry to launch it behind `tainttrap run`. None = not wrappable."""
    if _is_wrapped(entry):
        return entry
    if "command" not in entry:
        return None  # HTTP/SSE servers: wrap manually with `tainttrap run --url`
    out = {k: v for k, v in entry.items() if k not in ("command", "args")}
    return {
        **out,
        "command": binary,
        "args": ["run", "--server", name, "--", entry["command"], *(entry.get("args") or [])],
    }


def unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if not _is_wrapped(entry):
        return entry
    args = entry["args"]
    i = args.index("--")
    out = {k: v for k, v in entry.items() if k not in ("command", "args")}
    rest = args[i + 2 :]
    restored = {**out, "command": args[i + 1]}
    if rest:
        restored["args"] = rest
    return restored


def _mcp_path(client: str, config: Path | None) -> tuple[Path, str]:
    default, key = MCP_DEFAULT_CONFIG[client]
    return (config or Path.cwd() / default), key


@install.command("mcp")
@click.option("--client", type=click.Choice(list(MCP_DEFAULT_CONFIG)), required=True)
@click.option(
    "--config", type=click.Path(path_type=Path), help="Config file (default: per client)."
)
@click.option("--server", "servers", multiple=True, help="Only these servers (default: all).")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True)
def install_mcp(
    client: str, config: Path | None, servers: tuple[str, ...], dry_run: bool, yes: bool
) -> None:
    """Put the TaintTrap proxy in front of MCP servers in a client config."""
    path, key = _mcp_path(client, config)
    data = _load(path)
    entries = data.get(key) or {}
    if not entries:
        raise click.ClickException(f"{path}: no '{key}' entries")
    binary = tainttrap_binary()
    for name, entry in entries.items():
        if servers and name not in servers:
            continue
        wrapped = wrap_entry(name, entry, binary)
        if wrapped is None:
            click.echo(
                f"skip {name}: HTTP server; use `tainttrap run --server {name} --url <url>`",
                err=True,
            )
            continue
        entries[name] = wrapped
    _apply(path, {**data, key: entries}, dry_run, yes)


@uninstall.command("mcp")
@click.option("--client", type=click.Choice(list(MCP_DEFAULT_CONFIG)), required=True)
@click.option("--config", type=click.Path(path_type=Path))
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True)
def uninstall_mcp(client: str, config: Path | None, dry_run: bool, yes: bool) -> None:
    path, key = _mcp_path(client, config)
    data = _load(path)
    entries = {n: unwrap_entry(e) for n, e in (data.get(key) or {}).items()}
    _apply(path, {**data, key: entries}, dry_run, yes)
