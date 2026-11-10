"""Scripted MCP client that drives `tainttrap run` over stdio."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

FAKE = Path(__file__).resolve().parents[1] / "fixtures" / "fake_mcp_server.py"
CLI = [sys.executable, "-c", "from tainttrap.cli.main import cli; cli()"]


class ProxyClient:
    def __init__(
        self,
        counter: Path,
        legacy_only: bool = False,
        extra_env: dict[str, str] | None = None,
        task_file: Path | None = None,
    ):
        server = [sys.executable, str(FAKE), "--counter", str(counter)] + (
            ["--legacy-only"] if legacy_only else []
        )
        args = (
            [*CLI, "run", "--server", "fake"]
            + (["--task-file", str(task_file)] if task_file else [])
            + ["--", *server]
        )
        env = {**os.environ, "TAINTTRAP_NO_AUTOSTART": "1", **(extra_env or {})}
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        self._id = 0
        self.modern = False

    def send_raw(self, line: bytes) -> None:
        assert self.p.stdin
        self.p.stdin.write(line if line.endswith(b"\n") else line + b"\n")
        self.p.stdin.flush()

    def read_raw(self) -> bytes:
        assert self.p.stdout
        return self.p.stdout.readline()

    def request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bytes]:
        self._id += 1
        params = dict(params or {})
        if self.modern:
            params["_meta"] = {
                **params.get("_meta", {}),
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            }
        self.send_raw(
            json.dumps(
                {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
            ).encode()
        )
        raw = self.read_raw()
        return json.loads(raw), raw

    def handshake(self) -> str:
        resp, _ = self.request("server/discover")
        if "result" in resp:
            self.modern = True
            return "modern"
        self.request(
            "initialize",
            {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t"}},
        )
        self.send_raw(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
        return "legacy"

    def call(
        self, name: str, arguments: dict[str, Any], meta: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"name": name, "arguments": arguments}
        if meta:
            params["_meta"] = meta
        return self.request("tools/call", params)[0]

    def close(self) -> int:
        assert self.p.stdin
        self.p.stdin.close()
        return self.p.wait(timeout=10)
