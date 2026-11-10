"""Small client for the daemon's admin socket (used by the CLI only)."""

from __future__ import annotations

import json
import socket
from typing import Any

from tainttrap.core import paths


class DaemonUnavailable(RuntimeError):
    pass


def admin_request(op: str, timeout: float = 5.0, **fields: Any) -> dict[str, Any]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(paths.admin_socket()))
        s.sendall((json.dumps({"v": 1, "rid": "1", "op": op, **fields}) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        raise DaemonUnavailable(str(e)) from e
    finally:
        s.close()
    if not buf:
        raise DaemonUnavailable("no response")
    resp: dict[str, Any] = json.loads(buf.split(b"\n", 1)[0])
    return resp
