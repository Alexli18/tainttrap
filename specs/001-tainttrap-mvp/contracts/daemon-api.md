# Contract: Daemon protocol (adapters ↔ core)

This contract covers FR-004: all adapters talk to the same core through this protocol. The transport is research R-07.

## Transport

- **Unix domain sockets.** Each request and response is one JSON object per line, UTF-8 encoded. Every request has a client-chosen `rid`, and the response echoes it. A connection can carry several requests, and responses can come back out of order.
- **Check socket** (`<runtime>/tainttrap/check.sock`, 0600). It accepts only the operations listed under "Check socket operations". Any other `op` gets `{"ok":false,"error":"forbidden_op"}`.
- **Admin socket** (`<runtime>/tainttrap/admin.sock`). It is used only by the `tainttrap` CLI.
- Peers with a different UID are rejected. In hardened mode the admin socket is owned by `_tainttrap`, and only root can use the mutating operations.
- Every request carries a protocol version, `"v":1`. The daemon rejects an unknown major version with `{"ok":false,"error":"unsupported_version"}`.

## Check socket operations

### `task`
```json
{"v":1,"rid":"1","op":"task","session_id":"s1","cwd":"/repo","text":"Rebuild the project","source":"hook_prompt"}
→ {"rid":"1","ok":true}
```

### `observe` (fire-and-forget; the response is optional)
```json
{"v":1,"rid":"2","op":"observe","session_id":"s1","cwd":"/repo","call_id":"toolu_01","tool_name":"WebFetch","response":<any JSON>}
→ {"rid":"2","ok":true,"indexed_bytes":18234}
```
The response is flattened to strings: text, `structuredContent` values and resource text. It is capped at 1 MB per observation; the head and tail are kept and the overflow is logged.

### `check`
```json
{"v":1,"rid":"3","op":"check","adapter":"claude_code_hook","session_id":"s1","cwd":"/repo",
 "call_id":"toolu_02","tool_name":"Bash","server":null,
 "arguments":{"command":"rm -rf build/"},
 "task_hint":null,"deadline_ms":28000}
→ {"rid":"3","ok":true,
   "decision":{"outcome":"ask","enforced":true,"effective_outcome":"ask",
               "decided_by":"policy_default","reason":"Destructive command; matches the task but policy asks for deletions.",
               "reason_codes":["destructive","policy_ask_destructive"],"entry_id":"01J9…"},
   "approval":null}
```

- `task_hint` carries the task text from the MCP proxy, taken from `_meta`, the task file or the environment. A task already recorded for the session takes priority.
- `deadline_ms` is the time the adapter will wait. The core uses it to cap the model, judge and approval stages.
- **Approval.** Only the MCP proxy uses `approval`, when it has no in-band elicitation. If the outcome is `ask` and the adapter sent `"approval_channel":"daemon"`, the response is `{"approval":{"id":"apv_…","expires_at":"…"}}`. The adapter then sends an `await_approval` request.

### `await_approval`
```json
{"v":1,"rid":"4","op":"await_approval","id":"apv_…"}
→ {"rid":"4","ok":true,"result":"approved|denied|timed_out","by":"human","latency_s":12.4}
```

### `session_end`
```json
{"v":1,"rid":"5","op":"session_end","session_id":"s1"}
```

## Admin socket operations

| op | Who | Effect |
|----|-----|--------|
| `status` | any same-UID user | Mode, policy hash, model version and device tier, uptime, queue sizes, counts for the last hour |
| `approvals` (stream) | any same-UID user | Pushes the pending approvals as they arrive: id, task, tool, masked arguments, reason, expiry. It **never** includes a confirmation code. |
| `approve` / `deny` `{id, code}` | human-only | Needs the out-of-band code (see below) in a standard install, or root in a hardened install. |
| `reload` `{code}` | human-only | Needs the out-of-band code in a standard install, or root in a hardened install. Validates the new policy and the registry (FR-022). On success they are swapped in atomically. On error the last good policy is kept and the error is returned |
| `shutdown` | human-only | Logged. The daemon writes a `daemon_stopped` entry first |

**Out-of-band confirmation (S1).** Every human-only admin op in a standard install needs a 6-digit code: `approve`, `deny` and `reload`.
- The daemon generates the code per request and delivers it **only** through an out-of-band OS channel:
  - macOS: an `osascript` notification or dialog;
  - Linux: `notify-send` or `zenity`;
  - WSL: a `powershell.exe` toast.
- The code is never returned over any socket, never printed by the CLI, and never logged.
- The human types the code into the CLI. The CLI reads it from `/dev/tty` and refuses to run unless both stdin and stdout are TTYs.
- Three wrong codes cancel the request: an approval resolves to deny, a reload is refused. The event is logged.
- **No GUI channel** (headless SSH, no notifier):
  - daemon approvals are unavailable and resolve to deny with the reason "no secure approval channel; use hardened mode";
  - `reload` is refused too. The user edits the policy file (owner-only permissions) and restarts the daemon. The headless tier is weaker only in convenience, not in protection: a code shown on a terminal could be read by an agent that allocates itself a pseudo-terminal.
- **Hardened install:** the mutating admin ops need root (`sudo`), and no code is used.

## Errors

The error format is `{"rid","ok":false,"error":"<code>","detail":"…"}`. The codes are `bad_request`, `forbidden_op`, `unsupported_version`, `deadline_exceeded`, `model_unavailable`, `internal`.

When it gets an error or no response by the deadline, the adapter applies the failure mode itself (FR-026), because the core may be what failed.

## Latency budget for `check` (the targets behind SC-004)

| Stage | Budget |
|-------|--------|
| Parse, session lookup, registry lookup | ≤ 1 ms |
| Secret scan with the prefilter (5 KB of arguments) | ≤ 3 ms |
| Provenance lookup (all string arguments) | ≤ 2 ms |
| Dossier build and tokenize | ≤ 5 ms |
| Model (CPU INT8, ≤ 512 tokens, reference laptop) | ≤ 450 ms p95 |
| Log write (async, off the critical path) | 0 ms |

The judge and the human are not covered by SC-004. They apply only to escalated calls, which should be at most 10% of all checked calls (SC-003).
