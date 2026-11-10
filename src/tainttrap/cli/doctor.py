"""`tainttrap doctor`: is the protection actually wired up? (read-only)

Catches the quiet ways to lose protection: hooks missing or disabled (`disableAllHooks`),
managed-only hooks that skip ours, a hook timeout shorter than the approval wait, no
`onFailure: "block"`, a daemon that is down, or a stale hook.json.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import click

from tainttrap.cli.admin import DaemonUnavailable, admin_request
from tainttrap.cli.install import APPROVAL_MARGIN_S, MARKER
from tainttrap.core import paths
from tainttrap.core.policy import PolicyError, load_policy, policy_hash

MANAGED = (
    Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    Path("/etc/claude-code/managed-settings.json"),
)


def settings_files(cwd: Path) -> list[tuple[str, Path]]:
    return [
        ("user", Path.home() / ".claude" / "settings.json"),
        ("project", cwd / ".claude" / "settings.json"),
        ("local", cwd / ".claude" / "settings.local.json"),
        *(("managed", p) for p in MANAGED),
    ]


def _load(p: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _our_pre_tool(data: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for group in (data.get("hooks") or {}).get("PreToolUse", []) or []:
        for h in group.get("hooks", []) or []:
            if MARKER in str(h.get("command", "")) and "pre-tool" in str(h.get("command", "")):
                out.append(h)
    return out


def diagnose(cwd: Path, check_daemon: bool = True) -> list[tuple[str, str]]:
    """(level, message) with level in ok | warn | error."""
    out: list[tuple[str, str]] = []
    try:
        policy = load_policy(paths.policy_file())
    except PolicyError as e:
        return [("error", f"policy invalid: {'; '.join(e.problems)}")]
    try:
        if not check_daemon:
            raise LookupError
        st = admin_request("status", timeout=2)
        out.append(("ok", f"daemon running (pid {st['pid']}, mode {st['mode']})"))
        if st.get("degraded_scopes"):
            out.append(
                (
                    "warn",
                    f"{st['degraded_scopes']} session scope(s) in degraded mode: so many "
                    "destinations were evicted that unproven ones are treated as untrusted",
                )
            )
        if st["policy_hash"] != policy_hash(policy):
            out.append(
                ("warn", "the daemon runs an older policy than the file; reload or restart it")
            )
    except DaemonUnavailable:
        out.append(("error", "daemon not running: `tainttrap daemon start`"))
    except LookupError:
        pass
    try:
        hook_json = json.loads(paths.hook_settings_file().read_text())
        if hook_json.get("policy_hash") != policy_hash(policy):
            out.append(("warn", "hook.json does not match the policy file"))
    except (OSError, ValueError):
        out.append(("warn", "hook.json missing: the hook treats every call as a protecting mode"))

    found, managed_only = [], False
    config_change: list[str] = []
    for scope, p in settings_files(cwd):
        data = _load(p)
        if data is None:
            continue
        if data.get("disableAllHooks") is True:
            level = "error" if scope != "managed" else "warn"
            out.append((level, f"{p}: disableAllHooks is true — TaintTrap's hooks do not run"))
        if data.get("allowManagedHooksOnly") is True and scope == "managed":
            managed_only = True
        for h in _our_pre_tool(data):
            found.append((scope, p, h))
        if _has_config_change(data):
            config_change.append(scope)
        if (
            scope == "managed"
            and (data.get("permissions") or {}).get("disableBypassPermissionsMode") != "disable"
        ):
            out.append(
                ("warn", f"{p}: bypass mode is allowed; consider disableBypassPermissionsMode")
            )
    if not found:
        out.append(("error", "no TaintTrap PreToolUse hook in any Claude Code settings file"))
    if managed_only and not any(scope == "managed" for scope, _, _ in found):
        out.append(("error", "allowManagedHooksOnly is set but TaintTrap's hook is not managed"))
    for scope, p, h in found:
        need = policy.human.timeout_s + 10
        if h.get("onFailure") != "block":
            out.append(
                ("error", f"{p}: PreToolUse hook lacks onFailure: block (a crash lets calls run)")
            )
        if int(h.get("timeout", 600)) < need:
            out.append(
                (
                    "error",
                    f"{p}: hook timeout {h.get('timeout')} s < human.timeout_s + 10 = {need} s"
                    f" (re-run `tainttrap install claude-code`; it uses +{APPROVAL_MARGIN_S} s)",
                )
            )
        else:
            out.append(("ok", f"{scope}: PreToolUse hook installed ({p})"))

    if found and not config_change:
        out.append(
            ("warn", "no TaintTrap ConfigChange hook: settings edits are only seen by doctor")
        )
    elif config_change and "managed" not in config_change:
        out.append(
            (
                "warn",
                "ConfigChange hook is not managed: the same edit that disables hooks can remove it",
            )
        )

    errors_log = paths.home_dir() / "hook-errors.log"
    if errors_log.exists():
        day = time.time() - 86400
        recent = 0
        for line in errors_log.read_text().splitlines():
            try:
                recent += json.loads(line).get("ts", 0) > day
            except ValueError:
                continue
        if recent:
            out.append(("warn", f"{recent} hook errors in the last 24 h ({errors_log})"))
    return out


@click.command("doctor")
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Check that TaintTrap is really protecting Claude Code (read-only)."""
    results = diagnose(Path.cwd())
    if ctx.obj.get("json"):
        click.echo(json.dumps([{"level": lv, "message": m} for lv, m in results], indent=2))
    else:
        for level, msg in results:
            click.echo(f"[{level:5}] {msg}")
    if any(level == "error" for level, _ in results):
        sys.exit(1)


def _has_config_change(data: dict[str, Any]) -> bool:
    for group in (data.get("hooks") or {}).get("ConfigChange", []) or []:
        for h in group.get("hooks", []) or []:
            if MARKER in str(h.get("command", "")):
                return True
    return False
