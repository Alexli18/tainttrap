"""`tainttrap policy show|validate|mode` and `tainttrap daemon reload` (T062)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import click
import yaml

from tainttrap.cli.reload import interactive_reload
from tainttrap.core import paths
from tainttrap.core.policy import (
    PolicyError,
    default_policy_text,
    load_policy,
    policy_hash,
    validate_file,
)

_MODE_LINE = re.compile(r"^mode:\s*\S+.*$", re.M)


@click.group()
def policy() -> None:
    """Show, validate and change the policy."""


@policy.command("show")
@click.pass_context
def policy_show(ctx: click.Context) -> None:
    try:
        p = load_policy(paths.policy_file())
    except PolicyError as e:
        raise click.ClickException("; ".join(e.problems)) from e
    data = p.model_dump(mode="json", exclude_none=True)
    if ctx.obj.get("json"):
        import json

        click.echo(json.dumps({"policy_hash": policy_hash(p), "policy": data}, indent=2))
        return
    click.echo(f"# {paths.policy_file()}  hash {policy_hash(p)[:12]}")
    click.echo(yaml.safe_dump(data, sort_keys=False))


@policy.command("validate")
@click.argument("file", required=False, type=click.Path(path_type=Path))
def policy_validate(file: Path | None) -> None:
    path = file or paths.policy_file()
    if not path.exists():
        raise click.ClickException(f"{path} does not exist")
    problems = validate_file(path)
    for p in problems:
        click.echo(f"{path}: {p}", err=True)
    if problems:
        sys.exit(1)
    click.echo(f"{path}: valid")


@policy.command("mode")
@click.argument("mode", type=click.Choice(["observe", "soft", "strict"]))
def policy_mode(mode: str) -> None:
    """Switch the mode (edits policy.yaml, then reloads with confirmation)."""
    path = paths.policy_file()
    text = path.read_text() if path.exists() else default_policy_text()
    text = (
        _MODE_LINE.sub(f"mode: {mode}", text, count=1)
        if _MODE_LINE.search(text)
        else text + f"\nmode: {mode}\n"
    )
    path.write_text(text)
    problems = validate_file(path)
    if problems:
        raise click.ClickException("; ".join(problems))
    click.echo(f"{path}: mode {mode}")
    interactive_reload()


@click.command("reload")
def daemon_reload() -> None:
    """Re-validate the policy and registry and load them (needs the out-of-band code)."""
    interactive_reload()
