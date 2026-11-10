"""`tainttrap run --server NAME [--url URL] [--task-file PATH] -- CMD...` (T071)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click


@click.command(
    "run", context_settings={"ignore_unknown_options": True, "allow_interspersed_args": False}
)
@click.option(
    "--server", required=True, help="Name of the upstream MCP server (used in the registry)."
)
@click.option("--url", help="Streamable HTTP upstream instead of a command.")
@click.option("--task-file", type=click.Path(path_type=Path), help="File holding the user's task.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def run(server: str, url: str | None, task_file: Path | None, command: tuple[str, ...]) -> None:
    """Run the MCP proxy in front of one server (clients launch this)."""
    if bool(url) == bool(command):
        raise click.UsageError("give either --url or a server command after --")
    if url:
        from tainttrap.adapters.mcp_proxy.http import run_http

        code = asyncio.run(run_http(server, url, task_file))
    else:
        from tainttrap.adapters.mcp_proxy.stdio import run_stdio

        code = asyncio.run(run_stdio(server, list(command), task_file))
    sys.exit(code)
