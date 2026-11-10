"""Streamable HTTP upstream (T070): the proxy is a stdio server to the client and POSTs each
message to the upstream URL, relaying JSON or SSE responses back.

Standard library only, so it stays a transparent relay: the SDK's `Client` negotiates its own
protocol era, which would break era mirroring (research R-02). Server-initiated streams
(GET / subscriptions/listen) are not relayed in the MVP.
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from tainttrap.adapters.mcp_proxy.relay import Relay
from tainttrap.adapters.mcp_proxy.stdio import _stdin_reader

ACCEPT = "application/json, text/event-stream"


def _headers(msg: dict[str, Any] | None, session: str | None) -> dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": ACCEPT}
    if session:
        h["Mcp-Session-Id"] = session  # legacy-era sessions
    if msg:
        meta = (msg.get("params") or {}).get("_meta") or {}
        version = meta.get("io.modelcontextprotocol/protocolVersion")
        if version:
            h["MCP-Protocol-Version"] = str(version)
        if isinstance(msg.get("method"), str):
            h["Mcp-Method"] = msg["method"]
            name = (msg.get("params") or {}).get("name")
            if isinstance(name, str):
                h["Mcp-Name"] = name
    return h


def parse_sse(body: str) -> list[str]:
    out, data = [], []
    for line in body.splitlines():
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line.strip() and data:
            out.append("\n".join(data))
            data = []
    if data:
        out.append("\n".join(data))
    return out


class HttpUpstream:
    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self.url = url
        self.extra = headers or {}
        self.session: str | None = None

    def post(self, line: bytes) -> list[bytes]:
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            msg = None
        req = urllib.request.Request(  # noqa: S310 - the user-configured upstream URL
            self.url,
            data=line,
            headers={
                **_headers(msg if isinstance(msg, dict) else None, self.session),
                **self.extra,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as r:  # noqa: S310
                self.session = r.headers.get("Mcp-Session-Id") or self.session
                ctype = r.headers.get("Content-Type", "")
                body = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body, ctype = (
                e.read().decode("utf-8", errors="replace"),
                e.headers.get("Content-Type", ""),
            )
            if not body.strip().startswith("{"):
                rid = msg.get("id") if isinstance(msg, dict) else None
                if rid is None:
                    return []
                err = {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32603, "message": f"upstream HTTP {e.code}"},
                }
                return [json.dumps(err).encode() + b"\n"]
        if not body.strip():
            return []  # 202 Accepted for notifications
        messages = parse_sse(body) if "text/event-stream" in ctype else [body]
        return [m.strip().encode() + b"\n" for m in messages if m.strip()]


async def run_http(
    server: str, url: str, task_file: Path | None = None, headers: dict[str, str] | None = None
) -> int:
    upstream = HttpUpstream(url, headers)
    out_lock = asyncio.Lock()
    stdout = sys.stdout.buffer

    async def to_client(data: bytes) -> None:
        async with out_lock:
            stdout.write(data if data.endswith(b"\n") else data + b"\n")
            stdout.flush()

    relay: Relay

    async def to_upstream(data: bytes) -> None:
        for reply in await asyncio.to_thread(upstream.post, data):
            await relay.from_upstream(reply)

    relay = Relay(server=server, to_upstream=to_upstream, to_client=to_client, task_file=task_file)
    reader = await _stdin_reader()
    while line := await reader.readline():
        await relay.from_client(line)
    await relay.drain()
    return 0
