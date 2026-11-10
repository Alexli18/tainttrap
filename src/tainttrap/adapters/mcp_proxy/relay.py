"""Transparent JSON-RPC line relay between an MCP client and one upstream server
(contracts/mcp-proxy.md, research R-02).

Everything is forwarded byte-for-byte except `tools/call`, which is held until the daemon
decides. Results of tools/call, resources/read and prompts/get are copied to the daemon as
untrusted observations. The relay never translates between protocol eras.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tainttrap.client import failure_decision, hook_settings, runtime_dir
from tainttrap.core.rules.secrets import string_leaves
from tainttrap.hookclient import _autostart

# Responses to these carry tool output proper; responses to every other client request (tool,
# prompt and resource listings, server instructions, errors) are observed too (T136).
OBSERVED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
MAX_RAW_OBSERVE = 1024 * 1024  # characters of an unparseable response line to observe
TASK_META_KEY = "tainttrap/task"
CHECK_TIMEOUT_S = 30.0

WriteFn = Callable[[bytes], Awaitable[None]]


async def daemon_request(
    payload: dict[str, Any], timeout: float = CHECK_TIMEOUT_S
) -> dict[str, Any]:
    path = str(runtime_dir() / "check.sock")

    async def once() -> dict[str, Any]:
        reader, writer = await asyncio.open_unix_connection(path, limit=8 * 1024 * 1024)
        try:
            # ensure_ascii=False: escaped non-ASCII text can grow 6x and overflow the daemon's
            # line limit (T138).
            data = json.dumps({"v": 1, "rid": "1", **payload}, ensure_ascii=False)
            writer.write((data + "\n").encode())
            await writer.drain()
            line = await reader.readline()
            if not line:
                raise ConnectionError("daemon closed the connection")
            data: dict[str, Any] = json.loads(line)
            return data
        finally:
            writer.close()

    try:
        return await asyncio.wait_for(once(), timeout)
    except (FileNotFoundError, ConnectionRefusedError):
        if os.environ.get("TAINTTRAP_NO_AUTOSTART") == "1":
            raise
        await asyncio.to_thread(_autostart)
        return await asyncio.wait_for(once(), timeout)


def id_key(rid: Any) -> str:
    """JSON-RPC id as a dict key; 5 and 5.0 are the same id to a client (T134)."""
    if isinstance(rid, float) and rid.is_integer():
        rid = int(rid)
    return json.dumps(rid)


def cap_chunks(chunks: list[str], limit: int = MAX_RAW_OBSERVE) -> list[str]:
    """Head and tail of the text, so the observe request stays under the daemon's line limit."""
    if sum(len(c) for c in chunks) <= limit:
        return chunks
    joined = "\n".join(chunks)
    return [joined[: limit // 2], joined[-(limit // 2) :]]


def flatten_result(result: Any) -> list[str]:
    """All text a client could show the model from a result or an error object: every string
    leaf, not a whitelist of fields (T136)."""
    if result is None:
        return []
    return string_leaves(result)


@dataclass
class Relay:
    server: str
    to_upstream: WriteFn
    to_client: WriteFn
    cwd: str = field(default_factory=os.getcwd)
    task_file: Path | None = None
    era: str = "legacy"
    session_id: str = field(default_factory=lambda: f"mcp:{os.getpid()}")
    _pending: dict[str, str] = field(default_factory=dict)  # upstream request id -> method
    _handshakes: dict[str, str] = field(default_factory=dict)
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    legacy_elicitation: bool = False
    _elicit: dict[str, asyncio.Future[Any]] = field(default_factory=dict)
    _started: bool = False

    async def _daemon(
        self, payload: dict[str, Any], timeout: float = CHECK_TIMEOUT_S
    ) -> dict[str, Any]:
        """daemon_request, announcing this proxy's session first (see TaintTrapClient)."""
        if not self._started:
            self._started = True
            await daemon_request(
                {
                    "op": "session_start",
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "source": "proxy",
                },
                timeout,
            )
        return await daemon_request(payload, timeout)

    def _spawn(self, coro: Awaitable[Any]) -> None:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def _static_task(self) -> str | None:
        if self.task_file and self.task_file.exists():
            return self.task_file.read_text().strip() or None
        return os.environ.get("TAINTTRAP_TASK") or None

    # -- client -> upstream ------------------------------------------------------------------

    async def from_client(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            await self.to_upstream(line)
            return
        if not isinstance(msg, dict):
            await self.to_upstream(line)
            return
        method, rid = msg.get("method"), msg.get("id")
        if method is None and isinstance(rid, str) and rid in self._elicit:
            # The client's answer to our own elicitation/create: never forwarded upstream.
            fut = self._elicit.pop(rid)
            if not fut.done():
                fut.set_result(msg.get("result"))
            return
        if method == "initialize":
            caps = (msg.get("params") or {}).get("capabilities") or {}
            self.legacy_elicitation = "elicitation" in caps
        if rid is not None and method in ("server/discover", "initialize"):
            self._handshakes[id_key(rid)] = method
        if rid is not None and isinstance(method, str):
            name = (msg.get("params") or {}).get("name") if method == "tools/call" else None
            self._pending[id_key(rid)] = f"tool:{name}" if isinstance(name, str) else method
        if method == "tools/call" and rid is not None:
            self._spawn(self._check_and_forward(line, msg))
            return
        await self.to_upstream(line)

    async def _check_and_forward(self, line: bytes, msg: dict[str, Any]) -> None:
        params = msg.get("params") or {}
        meta = params.get("_meta") or {}
        if "io.modelcontextprotocol/protocolVersion" in meta:
            self.era = "modern"
        tool, arguments = str(params.get("name", "")), params.get("arguments") or {}
        if "requestState" in params and await self._resume_after_input(msg, tool, arguments):
            return
        task_hint = meta.get(TASK_META_KEY) or self._static_task()
        caps = meta.get("io.modelcontextprotocol/clientCapabilities") or {}
        if self.era == "modern":
            channel = "elicitation" if "elicitation" in caps else "daemon"
        else:
            channel = "elicitation" if self.legacy_elicitation else "daemon"
        payload = {
            "op": "check",
            "adapter": "mcp_proxy",
            "session_id": self.session_id,
            "cwd": self.cwd,
            "call_id": f"{self.server}:{json.dumps(msg.get('id'))}",
            "tool_name": str(params.get("name", "")),
            "server": self.server,
            "arguments": params.get("arguments") or {},
            "task_hint": task_hint,
            "deadline_ms": int(CHECK_TIMEOUT_S * 1000) - 500,
            "approval_channel": channel,
        }
        approval = None
        task = hint = ""
        try:
            resp = await self._daemon(payload)
            if not resp.get("ok"):
                raise RuntimeError(f"{resp.get('error')}: {resp.get('detail')}")
            d = resp["decision"]
            approval, task, hint = resp.get("approval"), d.get("task", ""), d.get("hint", "")
            outcome, reason, codes, entry_id = (
                d["effective_outcome"],
                d["reason"],
                d.get("reason_codes", []),
                d.get("entry_id", ""),
            )
        except Exception as e:  # noqa: BLE001 - daemon failure -> failure mode
            code = (
                "daemon_timeout"
                if isinstance(e, TimeoutError) or "daemon_timeout" in str(e)
                else "daemon_unavailable"
                if isinstance(e, OSError)
                else "internal_error"
            )
            fd = failure_decision(f"{type(e).__name__}: {e}", code)
            outcome, reason, codes, entry_id = (
                fd.effective_outcome,
                fd.reason,
                list(fd.reason_codes),
                "",
            )
        if outcome == "allow":
            await self.to_upstream(line)
            return
        if outcome == "ask":
            answer = await self._ask_human(
                msg, tool, arguments, reason, task, entry_id, channel, approval
            )
            if answer is None:  # modern-era InputRequiredResult already sent
                return
            if answer == "approved":
                await self.to_upstream(line)
                return
            reason = (
                "approval timed out" if answer == "timed_out" else f"denied by the user ({reason})"
            )
            codes = [*codes, f"human_{answer}"]
        self._pending.pop(json.dumps(msg.get("id")), None)
        await self.to_client(
            self.block_response(msg.get("id"), reason, codes, entry_id, outcome, hint)
        )

    async def _ask_human(
        self,
        msg: dict[str, Any],
        tool: str,
        arguments: Any,
        reason: str,
        task: str,
        entry_id: str,
        channel: str,
        approval: dict[str, Any] | None,
    ) -> str | None:
        from tainttrap.adapters.mcp_proxy import elicitation as el
        from tainttrap.core.masking import mask_json

        text = el.message_for(tool, self.server, reason, task, mask_json(arguments))
        if channel == "elicitation" and self.era == "modern":
            state = el.sign_state(tool, arguments, entry_id)
            self._pending.pop(json.dumps(msg.get("id")), None)
            await self.to_client(el.input_required_result(msg.get("id"), text, state))
            return None
        if channel == "elicitation":
            eid, req = el.legacy_elicitation_request(text)
            fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
            self._elicit[eid] = fut
            await self.to_client(req)
            try:
                result = await asyncio.wait_for(fut, human_timeout_s())
            except TimeoutError:
                self._elicit.pop(eid, None)
                answer = "timed_out"
            else:
                answer = "approved" if el.approved(result) else "denied"
            self._spawn(self._report_human(entry_id, answer, "elicitation"))
            return answer
        if approval:
            try:
                resp = await self._daemon(
                    {"op": "await_approval", "id": approval["id"]}, timeout=human_timeout_s() + 5
                )
                return str(resp.get("result", "denied"))
            except Exception:  # noqa: BLE001
                return "denied"
        return "denied"

    async def _resume_after_input(self, msg: dict[str, Any], tool: str, arguments: Any) -> bool:
        """Modern-era retry carrying our requestState. True if handled here."""
        from tainttrap.adapters.mcp_proxy import elicitation as el

        params = dict(msg.get("params") or {})
        ok, detail, entry_id = el.verify_state(params.get("requestState"), tool, arguments)
        if not ok and detail == "not a TaintTrap request state":
            return False  # the upstream server's own MRTR state: pass through untouched
        responses = dict(params.get("inputResponses") or {})
        answer = responses.pop(el.INPUT_KEY, None)
        if not ok or not el.approved(answer):
            human = "denied" if ok else "invalid"
            self._spawn(self._report_human(entry_id, human, "elicitation"))
            reason = detail if not ok else "denied by the user"
            await self.to_client(
                self.block_response(msg.get("id"), reason, [f"human_{human}"], entry_id)
            )
            return True
        params.pop("requestState", None)
        if responses:
            params["inputResponses"] = responses
        else:
            params.pop("inputResponses", None)
        self._spawn(self._report_human(entry_id, "approved", "elicitation"))
        await self.to_upstream((json.dumps({**msg, "params": params}) + "\n").encode())
        return True

    async def _report_human(self, entry_id: str, answer: str, channel: str) -> None:
        try:
            await self._daemon(
                {
                    "op": "human_answer",
                    "session_id": self.session_id,
                    "entry_id": entry_id,
                    "answer": answer,
                    "channel": channel,
                },
                timeout=5,
            )
        except Exception:  # noqa: BLE001,S110 - logging only
            pass

    def block_response(
        self,
        rid: Any,
        reason: str,
        codes: list[str],
        entry_id: str,
        outcome: str = "block",
        hint: str = "",
    ) -> bytes:
        # The hint (core/advice.py) replaces the generic advice; for a likely data leak it tells
        # the agent not to hand the call to the user.
        advice = hint or "If the user really wants this, ask them to confirm it explicitly."
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": f"[TaintTrap] Blocked: {reason}. {advice}"}],
            "isError": True,
            "_meta": {
                "tainttrap/decision": {
                    "outcome": outcome,
                    "reason_codes": codes,
                    "entry_id": entry_id,
                }
            },
        }
        if self.era == "modern":
            result = {"resultType": "complete", **result}
        return (json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n").encode()

    # -- upstream -> client ------------------------------------------------------------------

    async def from_upstream(self, line: bytes) -> None:
        await self.to_client(line)  # forward first; observation never delays the relay
        try:
            await self._observe_upstream(line)
        except Exception:  # noqa: BLE001 - a bad line must never stop the relay (T137)
            await self._observe_raw(line)

    async def _observe_upstream(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace")  # clients decode leniently too (T135)
        try:
            msg = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            await self._observe_raw(line)
            return
        if not isinstance(msg, dict) or "id" not in msg or "method" in msg:
            return
        key = id_key(msg["id"])
        hs = self._handshakes.pop(key, None)
        if hs and "result" in msg:
            self.era = "modern" if hs == "server/discover" else "legacy"
        method = self._pending.pop(key, None)
        if method is None:
            return
        chunks = flatten_result(msg.get("result")) + flatten_result(msg.get("error"))
        if chunks:
            self._spawn(self._observe(f"{self.server}:{key}", method, chunks))

    async def _observe_raw(self, line: bytes) -> None:
        """A line we could not read as a response still reached the client: index its text, as
        long as some request is waiting for an answer."""
        if not self._pending:
            return
        text = line.decode("utf-8", errors="replace")
        if len(text) > MAX_RAW_OBSERVE:
            half = MAX_RAW_OBSERVE // 2
            text = text[:half] + "\n" + text[-half:]
        self._spawn(self._observe(f"{self.server}:raw:{time.monotonic_ns()}", "unparsed", [text]))

    async def _observe(self, call_id: str, method: str, chunks: list[str]) -> None:
        chunks = cap_chunks(chunks)
        try:
            await self._daemon(
                {
                    "op": "observe",
                    "session_id": self.session_id,
                    "cwd": self.cwd,
                    "call_id": call_id,
                    "tool_name": method.removeprefix("tool:"),
                    "server": self.server,
                    "response": chunks,
                },
                timeout=10,
            )
        except Exception:  # noqa: BLE001,S110 - observation is best effort
            pass

    async def drain(self, timeout: float = 5.0) -> None:
        end = time.monotonic() + timeout
        while self._tasks and time.monotonic() < end:
            await asyncio.wait(set(self._tasks), timeout=max(0.01, end - time.monotonic()))


def human_timeout_s() -> float:
    return float((hook_settings() or {}).get("human_timeout_s", 60))
