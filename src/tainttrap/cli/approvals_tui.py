"""`tainttrap approvals`, `tainttrap approve ID`, `tainttrap deny ID` (T084, FR-024).

Interactive only: stdin and stdout must be terminals, and every answer needs the 6-digit code
the daemon shows in an OS dialog. There is no JSON listing (contracts/cli.md).
"""

from __future__ import annotations

import json
import sys
from typing import Any

import click

from tainttrap.cli.admin import DaemonUnavailable, admin_request
from tainttrap.cli.reload import read_code_from_tty, require_tty


def _admin(op: str, **fields: Any) -> dict[str, Any]:
    try:
        resp = admin_request(op, timeout=40, **fields)
    except DaemonUnavailable as e:
        click.echo(f"daemon not running: {e}", err=True)
        sys.exit(2)
    if not resp.get("ok"):
        raise click.ClickException(f"{resp.get('error')}: {resp.get('detail')}")
    return resp


def answer(pid: str, approve: bool) -> bool:
    ch = _admin("approval_challenge", id=pid)
    if not ch.get("found"):
        click.echo(f"{pid}: no longer pending")
        return False
    if ch.get("resolved"):
        click.echo(f"{pid}: {ch['resolved']} ({ch.get('detail')})")
        return False
    click.echo("A confirmation code was shown in a system dialog.")
    for _ in range(3):
        code = read_code_from_tty("Enter the 6-digit code: ")
        resp = admin_request(
            "approve" if approve else "deny", id=pid, challenge_id=ch["challenge_id"], code=code
        )
        if resp.get("ok"):
            click.echo(f"{pid}: {resp['result']}")
            return True
        click.echo(resp.get("detail", "refused"), err=True)
        if "cancelled" in resp.get("detail", "") or "no such" in resp.get("detail", ""):
            break
    return False


def render(p: dict[str, Any], waiting: int) -> str:
    args = json.dumps(p.get("arguments"), ensure_ascii=False)
    if len(args) > 300:
        args = args[:299] + "…"
    server = f"{p['server']}." if p.get("server") else ""
    return (
        f"\n── approval {p['id']}  ({waiting} waiting, {p['expires_in_s']:.0f} s left)\n"
        f"  task:   {p.get('task') or '(unknown)'}\n"
        f"  call:   {server}{p['tool']} {args}\n"
        f"  reason: {p.get('reason')}"
    )


@click.command("approvals")
def approvals() -> None:
    """Answer pending approvals one at a time, oldest first."""
    require_tty()
    click.echo("Waiting for approvals (Ctrl+C to quit)…")
    try:
        while True:
            pending = _admin("approvals", wait_s=20)["pending"]
            if not pending:
                continue
            p = pending[0]
            click.echo(render(p, len(pending)))
            key = click.prompt(
                "  [a]pprove / [d]eny / [s]kip", type=click.Choice(["a", "d", "s"]), default="s"
            )
            if key in ("a", "d"):
                answer(p["id"], key == "a")
    except KeyboardInterrupt:
        click.echo()


@click.command("approve")
@click.argument("approval_id")
def approve(approval_id: str) -> None:
    """Approve one pending call (needs the out-of-band code)."""
    require_tty()
    if not answer(approval_id, True):
        sys.exit(1)


@click.command("deny")
@click.argument("approval_id")
def deny(approval_id: str) -> None:
    """Deny one pending call (needs the out-of-band code)."""
    require_tty()
    if not answer(approval_id, False):
        sys.exit(1)
