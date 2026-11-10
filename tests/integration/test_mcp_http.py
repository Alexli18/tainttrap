import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tainttrap.adapters.mcp_proxy.http import HttpUpstream, parse_sse

SEEN = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append((self.headers, msg))
        if "id" not in msg:
            self.send_response(202)
            self.end_headers()
            return
        body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": msg["method"]}})
        if msg["method"] == "tools/call":
            payload = f"event: message\ndata: {body}\n\n".encode()
            ctype = "text/event-stream"
        else:
            payload, ctype = body.encode(), "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Mcp-Session-Id", "sess-1")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def test_http_upstream_json_sse_and_headers():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    up = HttpUpstream(f"http://127.0.0.1:{srv.server_port}/mcp")
    try:
        r1 = up.post(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
        assert json.loads(r1[0])["result"]["ok"] == "initialize"
        assert up.post(b'{"jsonrpc":"2.0","method":"notifications/initialized"}') == []
        r2 = up.post(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "x",
                        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
                    },
                }
            ).encode()
        )
        assert json.loads(r2[0])["id"] == 2
        headers = SEEN[-1][0]
        assert headers["Mcp-Session-Id"] == "sess-1" and headers["Mcp-Method"] == "tools/call"
        assert headers["Mcp-Name"] == "x" and headers["MCP-Protocol-Version"] == "2026-07-28"
    finally:
        srv.shutdown()


def test_parse_sse_multiple_events():
    assert parse_sse('data: {"a":1}\n\ndata: {"b":2}\n\n') == ['{"a":1}', '{"b":2}']
