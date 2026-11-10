"""`tainttrap init` (T060): default policy in observe mode, empty registry overrides."""

from __future__ import annotations

import importlib.util
import os

import click

from tainttrap.core import paths
from tainttrap.core.policy import default_policy_text


@click.command("init")
def init() -> None:
    """Write the default policy (observe mode) and registry file. Never overwrites."""
    cfg = paths.config_dir()
    os.chmod(cfg, 0o700)
    policy = paths.policy_file()
    if policy.exists():
        click.echo(f"{policy}: exists, left unchanged")
    else:
        policy.write_text(default_policy_text())
        click.echo(f"wrote {policy} (mode: observe — nothing is blocked until you switch modes)")
    registry = paths.user_registry_file()
    if not registry.exists():
        registry.write_text(
            "# Your own tools: name, risk_class, description (<= 300 chars).\ntools: []\n"
        )
        click.echo(f"wrote {registry}")
    if importlib.util.find_spec("onnxruntime") is None:
        click.echo(
            "model: no [cpu]/[gpu] extra installed; "
            "using the provenance heuristic until a model is pulled"
        )
    click.echo("\nnext steps:")
    click.echo("  tainttrap install claude-code   # Claude Code hooks")
    click.echo("  tainttrap daemon start")
    click.echo("  tainttrap report --since 1d     # what would have been blocked")
