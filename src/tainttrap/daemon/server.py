"""The resident daemon: two Unix sockets speaking line-delimited JSON (contracts/daemon-api.md)."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json
import logging
import os
import socket
import struct
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tainttrap.core import paths
from tainttrap.core.engine import CheckRequest, Engine
from tainttrap.core.masking import mask_json
from tainttrap.core.policy import Policy, policy_hash
from tainttrap.core.rules.secrets import string_leaves
from tainttrap.core.types import Adapter
from tainttrap.daemon.sessions import SessionStore
from tainttrap.logstore.writer import LogWriter

log = logging.getLogger("tainttrap.daemon")

PROTOCOL_VERSION = 1
MAX_OBSERVE_BYTES = 1024 * 1024
MAX_LINE = 8 * 1024 * 1024
HEARTBEAT_S = 60
ORDER_TIMEOUT_S = 20.0  # a check waits at most this long for earlier observations
ORDERED_OPS = frozenset({"observe", "task", "session_start"})
# A session that starts fresh: Claude Code's SessionStart sources that begin a new
# conversation, and the SDK client and MCP proxy, which announce a session when they open it.
FRESH_SOURCES = frozenset({"startup", "clear", "sdk", "proxy"})
_TICKET: contextvars.ContextVar[int] = contextvars.ContextVar("tainttrap_ticket", default=0)
DEDUP_WINDOW_S = 5.0

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class RequestError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def peer_uid(sock: socket.socket) -> int | None:
    try:
        if sys.platform.startswith("linux"):
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            return int(struct.unpack("3i", creds)[1])
        if sys.platform == "darwin":
            local_peercred = getattr(socket, "LOCAL_PEERCRED", 0x001)
            raw = sock.getsockopt(0, local_peercred, struct.calcsize("IIh16I") + 8)
            return int(struct.unpack_from("II", raw)[1])
    except OSError:
        return None
    return None


def flatten_response(response: Any) -> list[str]:
    """Tool output as text chunks, capped at 1 MB (head and tail kept). Every string, dict keys
    included, numbers as text; walked without recursion, so deep nesting is not an error
    (T137, T143)."""
    chunks = string_leaves(response) if not isinstance(response, str) else [response]
    total = sum(len(c) for c in chunks)
    if total <= MAX_OBSERVE_BYTES:
        return chunks
    joined = "\n".join(chunks)
    half = MAX_OBSERVE_BYTES // 2
    return [joined[:half], joined[-half:]]


def write_hook_settings(policy: Policy, path: Path | None = None) -> Path:
    path = path or paths.hook_settings_file()
    data = {
        "policy_hash": policy_hash(policy),
        "mode": policy.mode.value,
        "failure_mode": policy.failure_mode.value,
        "fail_closed_action": policy.fail_closed_action,
        "explicit_allow": policy.hook.explicit_allow,
        "approval_channel": policy.hook.approval_channel,
        "human_timeout_s": policy.human.timeout_s,
        "written_at": time.time(),
    }
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)
    return path


@dataclass
class Daemon:
    engine: Engine
    policy: Policy
    log_writer: LogWriter
    sessions: SessionStore = field(default_factory=SessionStore)
    check_path: Path = field(default_factory=paths.check_socket)
    admin_path: Path = field(default_factory=paths.admin_socket)
    hook_settings_path: Path | None = None
    started_at: float = field(default_factory=time.time)
    admin_handlers: dict[str, Handler] = field(default_factory=dict)
    integrity: Any = None
    approvals: Any = None
    _servers: list[asyncio.AbstractServer] = field(default_factory=list)
    _bg: list[asyncio.Task[Any]] = field(default_factory=list)
    _counts: dict[str, int] = field(default_factory=dict)
    _writers: set[asyncio.StreamWriter] = field(default_factory=set)
    _recent: dict[str, tuple[float, dict[str, Any]]] = field(default_factory=dict)
    # Asked-about directory recipients, keyed by call_id and decision entry_id, learned on approval.
    # Directory recipients asked about, keyed by decision entry_id; learned only when the human
    # approves through the daemon's own code-confirmed approval queue.
    _asked_entries: dict[str, tuple[str, list[str]]] = field(default_factory=dict)
    recipients: Any = None
    # Order: every request line gets a ticket when its first byte arrives; a check waits until
    # all lines with lower tickets are handled, so an observation that arrived before a check
    # is indexed before that check is decided, even if its sender stopped waiting (T154).
    _ticket: int = 0
    _open: set[int] = field(default_factory=set)
    _done: asyncio.Condition | None = None
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    observe_delay_s: float = 0.0  # tests only: set in-process, never reachable from a socket

    # -- lifecycle -------------------------------------------------------------------------

    async def start(self) -> None:
        for p in (self.check_path, self.admin_path):
            if p.exists():
                p.unlink()
        self._servers.append(
            await asyncio.start_unix_server(
                self._serve_check, path=str(self.check_path), limit=MAX_LINE
            )
        )
        self._servers.append(
            await asyncio.start_unix_server(
                self._serve_admin, path=str(self.admin_path), limit=MAX_LINE
            )
        )
        os.chmod(self.check_path, 0o600)
        os.chmod(self.admin_path, 0o600)
        self.apply_policy(self.policy)
        self.admin_handlers.setdefault("status", self._status)
        from tainttrap.daemon.recipients import RecipientStore

        if self.recipients is None:
            self.recipients = RecipientStore.load(paths.home_dir() / "approved_recipients.json")
        self.engine.known_recipients = self.recipients.known
        self.admin_handlers.update(
            recipients=self._admin_recipients, revoke_recipient=self._admin_revoke_recipient
        )
        from tainttrap.daemon.integrity import Integrity, register

        if self.integrity is None:
            self.integrity = Integrity()
        register(self, self.integrity)
        from tainttrap.daemon.approvals import Approvals

        self.approvals = Approvals(self.integrity, self._log_approval)
        self.admin_handlers.update(
            approvals=self._admin_approvals,
            approval_challenge=self._admin_approval_challenge,
            approve=self._admin_approve,
            deny=self._admin_deny,
        )
        self.log_writer.write(self._entry("daemon_started"))
        self._bg.append(asyncio.create_task(self._housekeeping()))

    async def stop(self) -> None:
        for t in self._bg:
            t.cancel()
        for s in self._servers:
            s.close()
        for w in list(self._writers):
            w.close()
        for s in self._servers:
            await s.wait_closed()
        # Let every connection and request task finish, so nothing of this daemon runs (or
        # logs) after stop() returns.
        if self._tasks:
            _, pending = await asyncio.wait(set(self._tasks), timeout=2)
            for t in pending:  # long waits (approvals, idle connections) end with the daemon
                t.cancel()
            if pending:
                await asyncio.wait(pending, timeout=5)
        self.log_writer.write(self._entry("daemon_stopped"))
        self.log_writer.flush()
        for p in (self.check_path, self.admin_path):
            p.unlink(missing_ok=True)

    def apply_policy(self, policy: Policy) -> None:
        from tainttrap.core.judge.base import make_judge

        self.policy = policy
        self.engine.judge = make_judge(policy.judge)
        write_hook_settings(policy, self.hook_settings_path)

    def _entry(self, kind: str, **extra: Any) -> dict[str, Any]:
        return {
            "kind": kind,
            "session_id": "-",
            "mode": self.policy.mode.value,
            "policy_hash": policy_hash(self.policy),
            **extra,
        }

    async def _housekeeping(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            self.log_writer.write(self._entry("heartbeat"))
            self.sessions.evict_idle()
            self.engine.provenance.evict_expired()

    # -- transport -------------------------------------------------------------------------

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dispatch: Handler
    ) -> None:
        sock = writer.get_extra_info("socket")
        uid = peer_uid(sock) if sock is not None else None
        if uid is not None and uid != os.getuid():
            writer.close()
            return
        lock = asyncio.Lock()
        self._writers.add(writer)
        me = asyncio.current_task()
        if me is not None:
            self._tasks.add(me)
            me.add_done_callback(self._tasks.discard)

        async def handle(line: bytes, ticket: int) -> None:
            rid = None
            try:
                _TICKET.set(ticket)
                req = json.loads(line)
                if not isinstance(req, dict):
                    raise RequestError("bad_request", "request must be an object")
                rid = req.get("rid")
                if req.get("v") != PROTOCOL_VERSION:
                    raise RequestError("unsupported_version", f"expected v={PROTOCOL_VERSION}")
                if req.get("op") not in ORDERED_OPS:
                    # Only observations and tasks must be in place before a later check;
                    # checks and long waits (approvals) never hold others back.
                    await self._close_ticket(ticket)
                resp = await dispatch(req)
                resp = {"rid": rid, "ok": True, **resp}
            except RequestError as e:
                resp = {"rid": rid, "ok": False, "error": e.code, "detail": e.detail}
            except json.JSONDecodeError as e:
                resp = {"rid": rid, "ok": False, "error": "bad_request", "detail": str(e)}
            except Exception as e:
                log.exception("internal error")
                resp = {"rid": rid, "ok": False, "error": "internal", "detail": type(e).__name__}
            finally:
                await self._close_ticket(ticket)
            data = (json.dumps(resp, ensure_ascii=False) + "\n").encode()
            try:
                async with lock:
                    writer.write(data)
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                # The request was fully handled (an observation is indexed); only the reply
                # could not be delivered because the client stopped waiting.
                log.debug("client gone before the reply to a handled request")

        try:
            while True:
                first = await reader.read(1)
                if not first:
                    break
                ticket = self._open_ticket()
                try:
                    rest = await reader.readline()
                except BaseException:
                    await self._close_ticket(ticket)
                    raise
                line = first + rest
                if not line.endswith(b"\n"):
                    log.warning("incomplete request line (%d bytes) dropped", len(line))
                    await self._close_ticket(ticket)
                    break
                t = asyncio.create_task(handle(line, ticket))
                self._tasks.add(t)
                t.add_done_callback(self._tasks.discard)
        except (asyncio.LimitOverrunError, ValueError) as e:
            # A request line over MAX_LINE: say so and log it instead of dropping it unseen (T138).
            log.warning("request line over %d bytes refused: %s", MAX_LINE, e)
            with contextlib.suppress(Exception):
                err = {"ok": False, "error": "too_large", "detail": f"line over {MAX_LINE} bytes"}
                writer.write((json.dumps(err) + "\n").encode())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    def _open_ticket(self) -> int:
        self._ticket += 1
        self._open.add(self._ticket)
        return self._ticket

    async def _close_ticket(self, ticket: int) -> None:
        if ticket in self._open:
            self._open.discard(ticket)
            if self._done is None:
                self._done = asyncio.Condition()
            async with self._done:
                self._done.notify_all()

    async def _wait_earlier(self, ticket: int, timeout: float) -> None:
        """Wait until every request that began before `ticket` was handled."""
        if self._done is None:
            self._done = asyncio.Condition()

        def earlier_done() -> bool:
            return not any(t < ticket for t in self._open)

        async with self._done:
            try:
                await asyncio.wait_for(self._done.wait_for(earlier_done), timeout)
            except TimeoutError:
                raise RequestError(
                    "daemon_timeout", "earlier observations were still being indexed"
                ) from None

    async def _serve_check(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await self._serve(r, w, self._dispatch_check)

    async def _serve_admin(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await self._serve(r, w, self._dispatch_admin)

    # -- check socket ----------------------------------------------------------------------

    def _session(self, req: dict[str, Any]) -> Any:
        """The request's session. One this daemon never saw start (it predates a restart, or
        its start was missed) is degraded at once: the observations it had are gone, and
        missing records must not read as trust (T155)."""
        sid = _str(req, "session_id")
        new = not self.sessions.known(sid)
        s = self.sessions.get(sid, req.get("cwd"))
        if new and req.get("op") != "session_start":
            self._degrade(s, "session started before this daemon (state lost)")
        return s

    def _degrade(self, session: Any, reason: str) -> None:
        if self.engine.provenance.mark_degraded(session.session_id):
            self.log_writer.write(
                self._entry("provenance_degraded", session_id=session.session_id, detail=reason)
            )

    async def _dispatch_check(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req.get("op")
        if op == "session_start":
            source = str(req.get("source") or "startup")
            new = not self.sessions.known(_str(req, "session_id"))
            s = self._session(req)
            if new and source not in FRESH_SOURCES:
                # A resumed or compacted conversation this daemon has no record of.
                self._degrade(s, f"session {source} without this daemon's records")
            return {}
        if op == "task":
            self._session(req)
            self.sessions.set_task(
                _str(req, "session_id"),
                _str(req, "text"),
                req.get("source", "hook_prompt"),
                req.get("cwd"),
            )
            return {}
        if op == "observe":
            if self.observe_delay_s:
                await asyncio.sleep(self.observe_delay_s)  # tests: simulate slow indexing
            s = self._session(req)
            chunks = flatten_response(req.get("response"))
            n = 0
            tool = req.get("tool_name")
            source = f"{req['server']}.{tool}" if req.get("server") and tool else tool
            for scope in s.scope_ids:
                n = self.engine.provenance.observe(scope, _str(req, "call_id"), chunks, source)
            for scope in self.engine.provenance.newly_degraded(s.scope_ids):
                # Once per scope: destinations not provably trusted now count as untrusted.
                self.log_writer.write(
                    self._entry(
                        "provenance_degraded",
                        session_id=s.session_id,
                        detail=f"evicted-destination filter full in scope {scope}",
                    )
                )
            if req.get("tool_name"):
                s.recent_actions.append(str(req["tool_name"]))
            return {"indexed_bytes": n}
        if op == "check":
            return await self._check(req)
        if op == "await_approval":
            answer, detail = await self.approvals.wait(_str(req, "id"))
            return {
                "result": answer,
                "detail": detail,
                "by": "human" if answer != "timed_out" else None,
            }
        if op == "human_answer":
            # An adapter's own channel (MCP elicitation) reports what the human chose. Logged only:
            # any same-user process can reach this socket, so it never teaches trusted recipients.
            self.log_writer.write(
                self._entry(
                    "approval",
                    session_id=req.get("session_id", "-"),
                    entry_ref=req.get("entry_id"),
                    human={
                        "answer": req.get("answer"),
                        "channel": req.get("channel", "elicitation"),
                    },
                )
            )
            return {}
        if op == "config_change":
            self._on_config_change(req)
            return {}
        if op == "session_end":
            sid = _str(req, "session_id")
            self.engine.provenance.drop_scope(sid)
            self.sessions.end(sid)
            return {}
        raise RequestError("forbidden_op", f"op {op!r} is not allowed on the check socket")

    async def _check(self, req: dict[str, Any]) -> dict[str, Any]:
        ticket = _TICKET.get()
        if ticket:
            await self._wait_earlier(ticket, ORDER_TIMEOUT_S)
        try:
            adapter = Adapter(req.get("adapter", "sdk"))
        except ValueError as e:
            raise RequestError("bad_request", "unknown adapter") from e
        args = req.get("arguments") or {}
        if not isinstance(args, dict):
            raise RequestError("bad_request", "arguments must be an object")
        session = self._session(req)
        task_hint = req.get("task_hint")
        if not session.task and not task_hint and session.cwd:
            task_hint = self.sessions.latest_task_for_cwd(
                session.cwd, self.policy.proxy.task_ttl_min
            )
        creq = CheckRequest(
            adapter=adapter,
            session_id=session.session_id,
            call_id=_str(req, "call_id"),
            tool_name=_str(req, "tool_name"),
            arguments=args,
            server=req.get("server"),
            cwd=req.get("cwd"),
            task_hint=task_hint,
            deadline_ms=req.get("deadline_ms"),
        )
        key = _dedup_key(creq.cwd, creq.server, creq.tool_name, args)
        if adapter is Adapter.MCP_PROXY and key in self._recent:
            ts, prior = self._recent[key]
            if time.monotonic() - ts <= DEDUP_WINDOW_S:
                dup = {
                    **prior,
                    "entry_id": self.log_writer.write(
                        self._entry(
                            "decision",
                            session_id=session.session_id,
                            adapter=adapter.value,
                            call={
                                "call_id": creq.call_id,
                                "tool_name": creq.tool_name,
                                "server": creq.server,
                            },
                            decision={
                                **{
                                    k: prior[k]
                                    for k in (
                                        "outcome",
                                        "enforced",
                                        "effective_outcome",
                                        "decided_by",
                                        "reason",
                                        "reason_codes",
                                    )
                                },
                                **({"hint": prior["hint"]} if prior.get("hint") else {}),
                                "dedup_of": prior["entry_id"],
                            },
                        )
                    ),
                }
                return {"decision": dup, "approval": None}
        result = await self.engine.decide(creq, session.view(), self.policy)
        entry_id = self.log_writer.write(result.log_entry)
        d = result.decision
        self._counts[d.outcome.value] = self._counts.get(d.outcome.value, 0) + 1
        decision = {
            "outcome": d.outcome.value,
            "enforced": d.enforced,
            "effective_outcome": d.effective_outcome.value,
            "decided_by": d.decided_by.value,
            "reason": d.reason,
            "reason_codes": list(d.reason_codes),
            "hint": d.hint,
            "blocked_parts": list(d.blocked_parts),
            "entry_id": entry_id,
            "task": (session.task or task_hint or "")[:200],
        }
        if (
            d.enforced
            and "recipient_from_directory" in d.reason_codes
            and d.effective_outcome.value == "ask"
        ):
            from tainttrap.core.rules.base import addressee_values

            tool_key = f"{creq.server}.{creq.tool_name}" if creq.server else creq.tool_name
            self._asked_entries[entry_id] = (tool_key, addressee_values(args))
        if adapter is Adapter.CLAUDE_CODE_HOOK and creq.server:
            now = time.monotonic()
            self._recent = {k: v for k, v in self._recent.items() if now - v[0] <= DEDUP_WINDOW_S}
            self._recent[key] = (now, decision)
        approval = None
        if req.get("approval_channel") == "daemon" and decision["effective_outcome"] == "ask":
            p = self.approvals.create(
                session.session_id,
                entry_id,
                {
                    "tool": creq.tool_name,
                    "server": creq.server,
                    "arguments": mask_json(result.log_entry["dossier"]["args"]),
                    "task": decision["task"],
                    "reason": decision["reason"],
                },
                self.policy.human.timeout_s,
            )
            approval = {"id": p.id, "expires_at": p.expires_at}
        return {"decision": decision, "approval": approval}

    # -- admin socket ----------------------------------------------------------------------

    async def _dispatch_admin(self, req: dict[str, Any]) -> dict[str, Any]:
        handler = self.admin_handlers.get(str(req.get("op")))
        if handler is None:
            raise RequestError("forbidden_op", f"unknown admin op {req.get('op')!r}")
        return await handler(req)

    def _on_config_change(self, req: dict[str, Any]) -> None:
        """A Claude Code settings file changed: log it and re-check that the hooks still run."""
        event = req.get("event") or {}
        self.log_writer.write(
            self._entry(
                "config_changed",
                session_id=req.get("session_id", "-"),
                detail=f"{event.get('source', '?')}: {event.get('file_path', '?')}"[:300],
            )
        )
        try:
            from pathlib import Path

            from tainttrap.cli.doctor import diagnose

            cwd = Path(req["cwd"]) if req.get("cwd") else Path.home()
            problems = [m for lv, m in diagnose(cwd, check_daemon=False) if lv == "error"]
        except Exception as e:  # noqa: BLE001 - never let the check crash the daemon
            problems = [f"could not verify hooks: {type(e).__name__}"]
        if problems:
            self.log_writer.write(self._entry("hooks_missing", detail="; ".join(problems)[:300]))
            notify = getattr(getattr(self.integrity, "provider", None), "notify", None)
            if callable(notify):
                import re

                short = re.sub(r"/(?:[^/\s]+/)+([^/\s]+/[^/\s:]+)", r"…/\1", problems[0])
                notify("TaintTrap protection changed: " + short[:160])

    def _learn_entry(self, entry_id: str) -> None:
        learned = self._asked_entries.pop(entry_id, None)
        if learned:
            tool_key, recipients = learned
            self.recipients.add(tool_key, recipients)

    async def _admin_recipients(self, req: dict[str, Any]) -> dict[str, Any]:
        return {"recipients": self.recipients.listing()}

    async def _admin_revoke_recipient(self, req: dict[str, Any]) -> dict[str, Any]:
        removed = self.recipients.revoke(_str(req, "address"), req.get("tool"))
        self.log_writer.write(
            self._entry("policy_reloaded", detail=f"revoked recipient ({removed} entries)")
        )
        return {"removed": removed}

    def _log_approval(self, p: Any, answer: str, detail: str) -> None:
        if answer == "approved":
            self._learn_entry(p.entry_id)
        self.log_writer.write(
            self._entry(
                "approval",
                session_id=p.session_id,
                entry_ref=p.entry_id,
                approval_id=p.id,
                human={
                    "answer": answer,
                    "latency_s": round(time.time() - p.created, 2),
                    "channel": "approvals_cli",
                },
                detail=detail,
            )
        )

    async def _admin_approvals(self, req: dict[str, Any]) -> dict[str, Any]:
        wait_s = float(req.get("wait_s") or 0)
        if wait_s > 0 and not self.approvals.list():
            await self.approvals.wait_changed(min(wait_s, 30))
        return {"pending": self.approvals.list()}  # never includes a code

    async def _admin_approval_challenge(self, req: dict[str, Any]) -> dict[str, Any]:
        return self.approvals.challenge(_str(req, "id"))

    async def _admin_approve(self, req: dict[str, Any]) -> dict[str, Any]:
        return self._answer(req, True)

    async def _admin_deny(self, req: dict[str, Any]) -> dict[str, Any]:
        return self._answer(req, False)

    def _answer(self, req: dict[str, Any], approve: bool) -> dict[str, Any]:
        ok, detail = self.approvals.answer(
            _str(req, "id"), str(req.get("challenge_id")), str(req.get("code")), approve
        )
        if not ok:
            raise RequestError("confirmation_failed", detail)
        return {"result": detail}

    async def _status(self, req: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": self.policy.mode.value,
            "policy_hash": policy_hash(self.policy),
            "model_version": getattr(self.engine.provider, "model_id", None),
            "device_tier": self.engine.tier,
            "uptime_s": round(time.time() - self.started_at, 1),
            "sessions": len(self.sessions),
            "degraded_scopes": sum(sc.degraded for sc in self.engine.provenance._scopes.values()),
            "counts": dict(self._counts),
            "pid": os.getpid(),
        }


def _str(req: dict[str, Any], key: str) -> str:
    v = req.get(key)
    if not isinstance(v, str) or not v:
        raise RequestError("bad_request", f"missing {key}")
    return v


def _dedup_key(cwd: str | None, server: str | None, tool: str, args: dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return "|".join((cwd or "", server or "", tool, hashlib.sha256(canonical.encode()).hexdigest()))
