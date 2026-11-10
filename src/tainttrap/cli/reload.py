"""Interactive policy reload with the out-of-band confirmation code (contracts/daemon-api.md)."""

from __future__ import annotations

import os
import sys

import click

from tainttrap.cli.admin import DaemonUnavailable, admin_request


def require_tty() -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise click.ClickException("this command needs an interactive terminal (stdin and stdout)")


def read_code_from_tty(prompt: str) -> str:
    """Prompt and read one line on the controlling terminal (not stdin/stdout)."""
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as e:
        raise click.ClickException(f"cannot open /dev/tty: {e}") from e
    try:
        os.write(fd, prompt.encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = os.read(fd, 64)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 256:
                break
        return buf.decode(errors="replace").strip()
    finally:
        os.close(fd)


def interactive_reload() -> None:
    """Ask the daemon for a challenge, read the code on the TTY, and reload. Exit 2 if no daemon."""
    try:
        ch = admin_request("reload_challenge")
    except DaemonUnavailable:
        click.echo("daemon not running; the new policy applies at the next start")
        return
    if not ch.get("ok"):
        raise click.ClickException(f"{ch.get('error')}: {ch.get('detail')}")
    if not ch.get("valid"):
        for p in ch.get("problems", []):
            click.echo(f"invalid policy: {p}", err=True)
        sys.exit(1)
    if ch.get("no_channel"):
        click.echo(ch["detail"], err=True)
        sys.exit(1)
    require_tty()
    click.echo("A confirmation code was shown in a system dialog.")
    for _ in range(3):
        code = read_code_from_tty("Enter the 6-digit code: ")
        resp = admin_request("reload", challenge_id=ch["challenge_id"], code=code)
        if resp.get("ok"):
            click.echo(f"policy reloaded: mode {resp['mode']}, hash {resp['policy_hash'][:12]}")
            return
        click.echo(resp.get("detail", "refused"), err=True)
        if "cancelled" in resp.get("detail", "") or "unknown" in resp.get("detail", ""):
            break
    os._exit(1)
