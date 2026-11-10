"""`tainttrap` admin CLI (contracts/cli.md).

Exit codes: 0 ok, 1 usage or validation error, 2 daemon unavailable.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from typing import Any

import click

from tainttrap.cli.admin import DaemonUnavailable, admin_request
from tainttrap.core import paths


def emit(ctx: click.Context, data: Any, text: str) -> None:
    if ctx.obj.get("json"):
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        click.echo(text)


@click.group()
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.version_option(package_name="tainttrap")
@click.pass_context
def cli(ctx: click.Context, as_json: bool) -> None:
    """TaintTrap: local check of every tool call an AI agent is about to make."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = as_json


@cli.group()
def daemon() -> None:
    """Start, stop and inspect the resident daemon."""


def _alive() -> bool:
    try:
        return bool(admin_request("status", timeout=1).get("ok"))
    except DaemonUnavailable:
        return False


@daemon.command("start")
@click.option("--foreground", is_flag=True)
def daemon_start(foreground: bool) -> None:
    if _alive():
        click.echo("daemon already running")
        return
    cmd = [sys.executable, "-m", "tainttrap.daemon"]
    if foreground:
        os.execv(sys.executable, cmd)  # noqa: S606
    log = (paths.home_dir() / "daemon.log").open("a")
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)  # noqa: S603
    for _ in range(100):
        if _alive():
            click.echo(f"daemon started (socket {paths.check_socket()})")
            return
        time.sleep(0.1)
    click.echo(f"daemon did not start; see {paths.home_dir() / 'daemon.log'}", err=True)
    sys.exit(2)


@daemon.command("stop")
def daemon_stop() -> None:
    pidfile = paths.home_dir() / "daemon.pid"
    try:
        pid = int(pidfile.read_text())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        click.echo("daemon not running", err=True)
        sys.exit(2)
    for _ in range(50):
        if not _alive():
            click.echo("daemon stopped")
            return
        time.sleep(0.1)
    click.echo("daemon did not stop in 5 s", err=True)
    sys.exit(2)


@daemon.command("status")
@click.pass_context
def daemon_status(ctx: click.Context) -> None:
    try:
        resp = admin_request("status")
    except DaemonUnavailable:
        emit(ctx, {"running": False}, "daemon not running")
        sys.exit(2)
    lines = [
        f"running   pid {resp['pid']}, up {resp['uptime_s']} s",
        f"mode      {resp['mode']}",
        f"policy    {resp['policy_hash'][:12]}",
        f"model     {resp['model_version']} (tier {resp['device_tier']})",
        f"sessions  {resp['sessions']}",
        f"decisions {resp['counts']}",
    ]
    emit(ctx, resp, "\n".join(lines))


cli.add_command(daemon_status, name="status")


def _register() -> None:
    from tainttrap.cli.approvals_tui import approvals, approve, deny
    from tainttrap.cli.doctor import doctor
    from tainttrap.cli.init import init
    from tainttrap.cli.install import install, uninstall
    from tainttrap.cli.log import log_cmd
    from tainttrap.cli.policy import daemon_reload, policy
    from tainttrap.cli.recipients import recipients
    from tainttrap.cli.report import report
    from tainttrap.cli.run import run

    for cmd in (
        init,
        install,
        uninstall,
        log_cmd,
        policy,
        report,
        run,
        approvals,
        approve,
        deny,
        recipients,
        doctor,
    ):
        cli.add_command(cmd)
    daemon.add_command(daemon_reload)


_register()
