"""`tainttrap log` and `tainttrap log show ENTRY_ID` (T057)."""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime, timedelta

import click

from tainttrap.core import paths
from tainttrap.logstore.writer import read_entries

_DURATION = re.compile(r"^(\d+)([smhdw])$")


def parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    m = _DURATION.match(value)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return datetime.now(UTC) - timedelta(seconds=seconds)
    try:
        d = datetime.fromisoformat(value)
    except ValueError as e:
        raise click.BadParameter(f"use e.g. 7d, 12h or an ISO date: {value}") from e
    return d if d.tzinfo else d.replace(tzinfo=UTC)


@click.group("log", invoke_without_command=True)
@click.option("--since", default="1d", show_default=True)
@click.option("--outcome", type=click.Choice(["allow", "ask", "block"]))
@click.option("--tool")
@click.option("--limit", type=int, default=50, show_default=True)
@click.pass_context
def log_cmd(
    ctx: click.Context, since: str, outcome: str | None, tool: str | None, limit: int
) -> None:
    """List decisions (secrets are masked)."""
    if ctx.invoked_subcommand:
        return
    rows = [
        e for e in read_entries(paths.logs_dir(), parse_since(since)) if e.get("kind") == "decision"
    ]
    if outcome:
        rows = [e for e in rows if e["decision"]["outcome"] == outcome]
    if tool:
        rows = [e for e in rows if e.get("call", {}).get("tool_name") == tool]
    rows = rows[-limit:]
    if ctx.obj.get("json"):
        click.echo(json.dumps(rows, indent=2))
        return
    for e in rows:
        d = e["decision"]
        would = "" if d["enforced"] else " (would)"
        click.echo(
            f"{e['entry_id']}  {e['ts'][:19]}  {d['outcome']:<5}{would:<8} "
            f"{e['call']['tool_name']:<14} {d['reason'][:90]}"
        )
    if not rows:
        click.echo("no decisions in range")


@log_cmd.command("show")
@click.argument("entry_id")
def log_show(entry_id: str) -> None:
    for e in read_entries(paths.logs_dir()):
        if e.get("entry_id") == entry_id:
            click.echo(json.dumps(e, indent=2, ensure_ascii=False))
            return
    click.echo(f"no entry {entry_id}", err=True)
    sys.exit(1)
