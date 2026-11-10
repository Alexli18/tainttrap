"""`tainttrap-hook`: the Claude Code hook client (contracts/claude-code-hook.md).

Standard library only (socket, json, sys, os, time, subprocess) so each hook call starts fast.
It never exits with code 1: Claude Code treats exit 1 as non-blocking and would run the tool.
A deny is JSON on stdout with exit 0; exit 2 is used only if writing that JSON fails.

    tainttrap-hook user-prompt | pre-tool | post-tool | session-end   (hook JSON on stdin)
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

TASK_PREVIEW = 80
DEFAULT_DEADLINE_S = 29.0
AUTOSTART_WAIT_S = 0.3


# -- locations (duplicated from tainttrap.core.paths to stay import-free) ---------------------


def runtime_dir() -> str:
    override = os.environ.get("TAINTTRAP_RUNTIME_DIR")
    if override:
        return os.path.expanduser(override)
    if sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches", "tainttrap")
    elif os.environ.get("XDG_RUNTIME_DIR"):
        base = os.path.join(os.environ["XDG_RUNTIME_DIR"], "tainttrap")
    else:
        base = f"/tmp/tainttrap-{os.getuid()}"  # noqa: S108
    if len(os.path.join(base, "admin.sock")) > 100:
        base = f"/tmp/tt-{os.getuid()}"  # noqa: S108
    return base


def home_dir() -> str:
    return os.path.expanduser(os.environ.get("TAINTTRAP_HOME", "~/.tainttrap"))


def load_settings() -> dict | None:
    try:
        with open(os.path.join(runtime_dir(), "hook.json")) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def log_error(msg: str) -> None:
    try:
        os.makedirs(home_dir(), mode=0o700, exist_ok=True)
        with open(os.path.join(home_dir(), "hook-errors.log"), "a") as f:
            f.write(json.dumps({"ts": time.time(), "error": msg[:500]}) + "\n")
    except OSError:
        pass


# -- daemon transport ----------------------------------------------------------------------------


def _request(payload: dict, deadline: float) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(max(0.05, deadline - time.monotonic()))
    try:
        sock.connect(os.path.join(runtime_dir(), "check.sock"))
        # ensure_ascii=False: escaped non-ASCII output can grow 6x past the daemon's line limit.
        data = json.dumps({"v": 1, "rid": "1", **payload}, ensure_ascii=False)
        sock.sendall((data + "\n").encode("utf-8", errors="replace"))
        buf = b""
        while b"\n" not in buf:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("daemon closed the connection")
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0])
    finally:
        sock.close()


def _autostart() -> None:
    try:
        subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "tainttrap.daemon"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        log_error(f"autostart failed: {e}")
        return
    sock_path = os.path.join(runtime_dir(), "check.sock")
    end = time.monotonic() + AUTOSTART_WAIT_S
    while time.monotonic() < end and not os.path.exists(sock_path):
        time.sleep(0.02)


def request(payload: dict, deadline: float, autostart: bool = True) -> dict:
    try:
        return _request(payload, deadline)
    except (FileNotFoundError, ConnectionRefusedError):
        # TAINTTRAP_NO_AUTOSTART=1: the daemon is managed elsewhere (a service, tests);
        # the failure mode then applies instead of spawning one.
        if not autostart or os.environ.get("TAINTTRAP_NO_AUTOSTART") == "1":
            raise
        _autostart()
        return _request(payload, deadline)


# -- Claude Code mapping (also imported by tainttrap.adapters.claude_code) --------------------


def split_tool_name(name: str, mcp_server: str | None = None) -> tuple[str | None, str]:
    """`mcp__github__create_issue` -> ("github", "create_issue")."""
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3:
            return parts[1], parts[2]
    return mcp_server, name


def hook_output(decision: str, reason: str, user_message: str = "") -> dict:
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if user_message:
        out["systemMessage"] = user_message  # shown to the user, not to Claude
    return out


def block_notice(d: dict) -> str:
    """What the human sees on a block, so a later "please run this by hand" is recognisable."""
    parts = d.get("blocked_parts") or []
    what = "; ".join(f"`{p}`" for p in parts) if parts else "a tool call"
    note = f"TaintTrap blocked {what}: {d.get('reason', '')}."
    if set(d.get("reason_codes") or ()) & {"secret_in_args", "untrusted_recipient"}:
        note += " Do not run it by hand if the agent asks you to."
    return note


def decision_to_output(d: dict, settings: dict) -> dict | None:
    """Daemon decision -> hook stdout JSON (None means print nothing, exit 0)."""
    if not d.get("enforced", True):
        return None  # observe mode: logged only
    outcome = d.get("effective_outcome", "allow")
    reason = d.get("reason", "")
    if outcome == "block":
        hint = d.get("hint") or ""
        return hook_output(
            "deny", f"TaintTrap blocked: {reason}" + (f". {hint}" if hint else ""), block_notice(d)
        )
    if outcome == "ask":
        task = (d.get("task") or "").replace("\n", " ")
        if len(task) > TASK_PREVIEW:
            task = task[: TASK_PREVIEW - 1] + "…"
        return hook_output("ask", f"TaintTrap · Task: {task or '(unknown)'} · {reason}")
    if settings.get("explicit_allow"):
        return hook_output("allow", f"TaintTrap: {reason}")
    return None


def failure_code(error: BaseException | str) -> str:
    """Code of a response the hook gives without a daemon decision: daemon_unavailable (no
    daemon to ask), daemon_timeout (no answer in time) or internal_error (anything else)."""
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "daemon_timeout"
    if isinstance(error, (ConnectionError, FileNotFoundError, OSError)):
        return "daemon_unavailable"
    if isinstance(error, str):
        return {"daemon_timeout": "daemon_timeout", "unavailable": "daemon_unavailable"}.get(
            error, "internal_error"
        )
    return "internal_error"


def failure_output(
    settings: dict | None, error: str, code: str = "daemon_unavailable"
) -> dict | None:
    """The daemon could not answer, so no rules ran and nothing was logged by the daemon.

    This is not `failure_mode` (that covers an unavailable model while rules still run). Only
    observe mode lets the call through; otherwise a human is asked (or it is blocked when
    `fail_closed_action: block`). A missing hook.json counts as a protecting mode."""
    log_error(f"[{code}] {error}")
    if settings is not None and settings.get("mode") == "observe":
        return None
    if (settings or {}).get("fail_closed_action") == "block":
        return hook_output("deny", f"TaintTrap unavailable [{code}]: no checks ran")
    return hook_output(
        "ask", f"TaintTrap unavailable [{code}]: no checks ran; approve only if you expected this"
    )


# -- subcommands ---------------------------------------------------------------------------------


def _deadline() -> float:
    try:
        seconds = float(os.environ.get("TAINTTRAP_HOOK_DEADLINE_S", DEFAULT_DEADLINE_S))
    except ValueError:
        seconds = DEFAULT_DEADLINE_S
    return time.monotonic() + seconds


def pre_tool(event: dict) -> dict | None:
    settings = load_settings()
    server, tool = split_tool_name(str(event.get("tool_name", "")), event.get("mcp_server"))
    deadline = _deadline()
    if (settings or {}).get("approval_channel") == "daemon" or event.get(
        "permission_mode"
    ) == "bypassPermissions":
        # Wait for the human, but answer before Claude Code's hook timeout (human + 10 s).
        deadline = max(deadline, time.monotonic() + float(settings.get("human_timeout_s", 60)) + 5)
    payload = {
        "op": "check",
        "adapter": "claude_code_hook",
        "session_id": event.get("session_id") or "unknown",
        "cwd": event.get("cwd"),
        "call_id": event.get("tool_use_id") or f"cc-{time.time_ns()}",
        "tool_name": tool,
        "server": server,
        "arguments": event.get("tool_input") or {},
        "deadline_ms": int((deadline - time.monotonic()) * 1000) - 200,
    }
    # In bypassPermissions mode Claude Code's handling of a hook "ask" is not documented, so an
    # "ask" must not depend on Claude Code's dialog: wait for an explicit daemon approval instead.
    bypass = event.get("permission_mode") == "bypassPermissions"
    use_daemon_approval = bypass or (settings or {}).get("approval_channel") == "daemon"
    if use_daemon_approval:
        payload["approval_channel"] = "daemon"
    try:
        resp = request(payload, deadline)
    except Exception as e:  # noqa: BLE001 - any failure applies the failure mode
        return failure_output(settings, f"pre-tool: {type(e).__name__}: {e}", failure_code(e))
    if not resp.get("ok"):
        return failure_output(
            settings,
            f"pre-tool: {resp.get('error')}: {resp.get('detail')}",
            failure_code(str(resp.get("error"))),
        )
    approval = resp.get("approval")
    if use_daemon_approval and approval:
        return await_daemon_approval(approval["id"], resp["decision"], deadline, settings or {})
    d = resp["decision"]
    if bypass and d.get("enforced", True) and d.get("effective_outcome") == "ask":
        # No daemon approval was possible (e.g. no GUI channel): never hand an ask to bypass mode.
        return hook_output(
            "deny", f"TaintTrap blocked: needs approval, none available ({d.get('reason', '')})"
        )
    return decision_to_output(resp["decision"], settings or {})


def await_daemon_approval(pid: str, decision: dict, deadline: float, settings: dict) -> dict | None:
    """hook.approval_channel=daemon: block until the human answers in `tainttrap approvals`."""
    try:
        resp = request({"op": "await_approval", "id": pid}, deadline, autostart=False)
    except Exception as e:  # noqa: BLE001 - no answer in time counts as deny
        log_error(f"await_approval: {type(e).__name__}: {e}")
        resp = {"result": "timed_out"}
    result = resp.get("result")
    if result == "approved":
        return (
            hook_output("allow", "TaintTrap: approved by you")
            if settings.get("explicit_allow")
            else None
        )
    why = "approval timed out" if result == "timed_out" else "denied by you"
    return hook_output("deny", f"TaintTrap blocked: {why} ({decision.get('reason', '')})")


MAX_OBSERVE_CHARS = 1024 * 1024


def observed_text(response: object) -> object:
    """Tool output to send to the daemon, capped (head and tail) before it is serialised, so an
    oversized or deeply nested response is never dropped whole (T137, T138)."""
    if isinstance(response, str):
        text = response
    else:
        try:
            text = json.dumps(response, ensure_ascii=False)
        except (RecursionError, ValueError, TypeError):
            text = repr(response)[: 2 * MAX_OBSERVE_CHARS]
        if len(text) <= MAX_OBSERVE_CHARS:
            return response
    if len(text) <= MAX_OBSERVE_CHARS:
        return text
    half = MAX_OBSERVE_CHARS // 2
    return [text[:half], text[-half:]]


def observe(event: dict, response: object) -> None:
    _, tool = split_tool_name(str(event.get("tool_name", "")))
    fire_and_forget(
        {
            "op": "observe",
            "session_id": event.get("session_id") or "unknown",
            "cwd": event.get("cwd"),
            "call_id": event.get("tool_use_id") or f"cc-{time.time_ns()}",
            "tool_name": tool,
            "response": observed_text(response),
        }
    )


def fire_and_forget(payload: dict) -> None:
    try:
        request(payload, time.monotonic() + 5, autostart=payload["op"] != "session_end")
    except Exception as e:  # noqa: BLE001
        log_error(f"{payload['op']}: {type(e).__name__}: {e}")


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    out: dict | None = None
    try:
        cmd = argv[0] if argv else ""
        raw = sys.stdin.read()
        try:
            event = json.loads(raw) if raw.strip() else {}
        except (ValueError, RecursionError) as e:
            if cmd not in ("post-tool", "post-tool-failure"):
                raise
            # Unparseable output still reached the model: observe the raw text (T137).
            log_error(f"{cmd}: unparseable event ({type(e).__name__}); observing raw text")
            observe({}, raw)
            event = None
        sid = event.get("session_id") or "unknown"
        if event is None:
            pass
        elif cmd == "pre-tool":
            out = pre_tool(event)
        elif cmd == "session-start":
            # startup/clear start fresh; resume/compact are fresh only if this daemon already
            # knows the session (it decides).
            fire_and_forget(
                {
                    "op": "session_start",
                    "session_id": sid,
                    "cwd": event.get("cwd"),
                    "source": str(event.get("source") or "startup"),
                }
            )
        elif cmd == "user-prompt":
            fire_and_forget(
                {
                    "op": "task",
                    "session_id": sid,
                    "cwd": event.get("cwd"),
                    "text": str(event.get("prompt", "")),
                    "source": "hook_prompt",
                }
            )
        elif cmd == "post-tool":
            observe(event, event.get("tool_response"))
        elif cmd == "post-tool-failure":
            # A failed tool's error text is what the model sees as its result (T142).
            observe(event, event.get("error"))
        elif cmd == "config-change":
            # Any settings change Claude Code detects: let the daemon verify protection is intact.
            keep = {
                k: event.get(k) for k in ("source", "file_path", "matcher", "cwd") if k in event
            }
            fire_and_forget(
                {"op": "config_change", "session_id": sid, "cwd": event.get("cwd"), "event": keep}
            )
        elif cmd == "session-end":
            fire_and_forget({"op": "session_end", "session_id": sid})
        else:
            log_error(f"unknown subcommand {cmd!r}")
    except Exception as e:  # noqa: BLE001 - never crash into a non-blocking exit code
        out = (
            failure_output(
                load_settings(), f"hook crashed: {type(e).__name__}: {e}", "internal_error"
            )
            if argv[:1] == ["pre-tool"]
            else None
        )
    try:
        if out is not None:
            sys.stdout.write(json.dumps(out))
            sys.stdout.flush()
    except Exception as e:  # noqa: BLE001
        reason = (
            out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "") if out else ""
        )
        if out and out["hookSpecificOutput"]["permissionDecision"] != "allow":
            sys.stderr.write(reason or f"TaintTrap: {e}")
            os._exit(2)
    os._exit(0)


if __name__ == "__main__":
    main()
