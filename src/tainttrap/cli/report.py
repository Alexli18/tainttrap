"""`tainttrap report` (T063)."""

from __future__ import annotations

import json

import click

from tainttrap.cli.log import parse_since
from tainttrap.core import paths
from tainttrap.logstore.report import build_report
from tainttrap.logstore.writer import read_entries


@click.command("report")
@click.option("--since", default="7d", show_default=True)
@click.option("--until", "until_", default=None)
@click.option("--by", type=click.Choice(["risk", "tool", "reason"]))
@click.pass_context
def report(ctx: click.Context, since: str, until_: str | None, by: str | None) -> None:
    """Counts of checked, allowed, blocked and asked calls (would-be counts in observe mode)."""
    entries = read_entries(paths.logs_dir(), parse_since(since))
    end = parse_since(until_) if until_ else None
    if end:
        entries = [e for e in entries if e.get("ts", "") <= end.isoformat()]
    r = build_report(entries, by)
    if ctx.obj.get("json"):
        click.echo(json.dumps(r.as_dict(), indent=2))
        return
    prefix = "would be " if r.would_be else ""
    click.echo(
        f"since {since}: {r.checked} calls checked"
        + ("  (observe mode: nothing enforced)" if r.would_be else "")
    )
    for label, n in (
        ("allowed", r.allowed),
        (f"{prefix}blocked", r.blocked),
        (f"{prefix}asked", r.asked),
        ("sent to judge", r.sent_to_judge),
        ("approval timed out", r.timed_out),
        ("failure mode", r.failure_mode),
        ("sessions in degraded mode", r.degraded_sessions),
        ("flagged as wrong", r.flagged),
    ):
        click.echo(f"  {label:<20} {n}")
    for key, counts in sorted(r.by.items()):
        click.echo(f"  {key:<28} " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
