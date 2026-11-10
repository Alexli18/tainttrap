"""Human approval through the MCP client itself (T083, research R-02).

* 2026-07-28 era: answer the held `tools/call` with an InputRequiredResult carrying a form
  elicitation and an HMAC-signed `requestState`; the client retries with `inputResponses`.
* Legacy era: send a server->client `elicitation/create` request (ids `ag-<ulid>`) and hold
  the call until the answer arrives.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from tainttrap.logstore.writer import new_ulid

INPUT_KEY = "tainttrap/approval"
STATE_TTL_S = 600
_KEY = secrets.token_bytes(32)  # per-process: a state is only valid for this proxy instance

APPROVAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "title": "Allow this tool call?",
            "enum": ["approve", "deny"],
            "enumNames": ["Approve", "Deny"],
        }
    },
    "required": ["decision"],
}


def args_digest(tool: str, arguments: Any) -> str:
    canonical = json.dumps(
        {"t": tool, "a": arguments}, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_state(tool: str, arguments: Any, entry_id: str, ttl_s: float = STATE_TTL_S) -> str:
    body = {
        "d": args_digest(tool, arguments),
        "exp": time.time() + ttl_s,
        "e": entry_id,
        "n": secrets.token_hex(4),
    }
    raw = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()
    mac = hmac.new(_KEY, raw.encode(), hashlib.sha256).hexdigest()
    return f"ag1.{raw}.{mac}"


def verify_state(state: Any, tool: str, arguments: Any) -> tuple[bool, str, str]:
    """Returns (ok, detail, entry_id)."""
    if not isinstance(state, str) or not state.startswith("ag1."):
        return False, "not a TaintTrap request state", ""
    try:
        _, raw, mac = state.split(".", 2)
        expected = hmac.new(_KEY, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return False, "approval state signature is invalid", ""
        body = json.loads(base64.urlsafe_b64decode(raw.encode()))
    except (ValueError, json.JSONDecodeError):
        return False, "approval state is malformed", ""
    if time.time() > float(body["exp"]):
        return False, "approval state expired", ""
    if body["d"] != args_digest(tool, arguments):
        return False, "approval was for a different call", ""
    return True, "ok", str(body.get("e", ""))


def message_for(tool: str, server: str, reason: str, task: str, masked_args: Any) -> str:
    args = json.dumps(masked_args, ensure_ascii=False)
    if len(args) > 400:
        args = args[:399] + "…"
    return (
        f"TaintTrap: {server}.{tool} needs your approval.\n"
        f"Task: {task or '(unknown)'}\nWhy: {reason}\nArguments: {args}"
    )


def input_required_result(rid: Any, message: str, state: str) -> bytes:
    result = {
        "resultType": "input_required",
        "inputRequests": {
            INPUT_KEY: {
                "method": "elicitation/create",
                "params": {"mode": "form", "message": message, "requestedSchema": APPROVAL_SCHEMA},
            }
        },
        "requestState": state,
    }
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n").encode()


def legacy_elicitation_request(message: str) -> tuple[str, bytes]:
    rid = f"tt-{new_ulid()}"
    req = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "elicitation/create",
        "params": {"message": message, "requestedSchema": APPROVAL_SCHEMA},
    }
    return rid, (json.dumps(req) + "\n").encode()


def approved(elicit_result: Any) -> bool:
    """`{action: accept, content: {decision: approve}}` is the only approval."""
    if not isinstance(elicit_result, dict):
        return False
    content = elicit_result.get("content") or {}
    return elicit_result.get("action") == "accept" and content.get("decision") == "approve"
