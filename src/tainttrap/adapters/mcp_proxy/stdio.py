"""stdio transport: the client launches the proxy, the proxy launches the real server (T067)."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from tainttrap.adapters.mcp_proxy.relay import Relay

MAX_LINE = 16 * 1024 * 1024


async def _stdin_reader() -> asyncio.StreamReader:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_LINE)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    return reader


async def run_stdio(server: str, command: list[str], task_file: Path | None = None) -> int:
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # the server's logs go straight to the client's stderr
        env=os.environ.copy(),
        limit=MAX_LINE,
    )
    assert proc.stdin is not None and proc.stdout is not None
    out_lock, up_lock = asyncio.Lock(), asyncio.Lock()
    stdout = sys.stdout.buffer

    async def to_client(data: bytes) -> None:
        async with out_lock:
            stdout.write(data if data.endswith(b"\n") else data + b"\n")
            stdout.flush()

    async def to_upstream(data: bytes) -> None:
        assert proc.stdin is not None
        async with up_lock:
            proc.stdin.write(data if data.endswith(b"\n") else data + b"\n")
            await proc.stdin.drain()

    relay = Relay(server=server, to_upstream=to_upstream, to_client=to_client, task_file=task_file)

    async def pump_client() -> None:
        reader = await _stdin_reader()
        while line := await reader.readline():
            await relay.from_client(line)
        await relay.drain()
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()

    async def pump_upstream() -> None:
        assert proc.stdout is not None
        while line := await proc.stdout.readline():
            await relay.from_upstream(line)

    client_task = asyncio.create_task(pump_client())
    await pump_upstream()  # upstream EOF (exit or crash) ends the proxy
    code = await proc.wait()
    await relay.drain(2)
    client_task.cancel()
    return code
