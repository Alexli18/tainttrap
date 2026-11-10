"""`tainttrap recipients list|revoke` — recipients a human approved, per tool."""

from __future__ import annotations

import json
import sys

import click

from tainttrap.cli.admin import DaemonUnavailable, admin_request


@click.group()
def recipients() -> None:
    """Show or revoke remembered (human-approved) recipients."""


def _call(op: str, **fields: object) -> dict:  # type: ignore[type-arg]
    try:
        resp = admin_request(op, **fields)
    except DaemonUnavailable:
        click.echo("daemon not running", err=True)
        sys.exit(2)
    if not resp.get("ok"):
        raise click.ClickException(f"{resp.get('error')}: {resp.get('detail')}")
    return resp


@recipients.command("list")
@click.pass_context
def recipients_list(ctx: click.Context) -> None:
    rows = _call("recipients")["recipients"]
    if ctx.obj.get("json"):
        click.echo(json.dumps(rows, indent=2))
        return
    for r in rows:
        click.echo(f"{r['tool']:<28} {r['address']}")
    if not rows:
        click.echo("no remembered recipients")


@recipients.command("revoke")
@click.argument("address")
@click.option("--tool", help="Only for this tool (e.g. send_email or gmail.send_message).")
def recipients_revoke(address: str, tool: str | None) -> None:
    removed = _call("revoke_recipient", address=address, tool=tool)["removed"]
    click.echo(f"revoked {removed} entr{'y' if removed == 1 else 'ies'} for {address}")
