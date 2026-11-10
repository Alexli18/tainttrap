# Contract: MCP proxy adapter

This contract covers FR-001, FR-002, FR-004, FR-006, FR-011, FR-024, FR-026 and FR-033. MCP facts were checked against spec revision `2026-07-28` and the Python SDK `mcp` 2.3.0 (research R-02).

## Invocation

```text
tainttrap run --server <name> [--task-file PATH] [--url URL] -- <real server command> [args…]
```

- **One proxy instance per upstream server.** This is the default mode. Tool names stay the same, so client permission rules such as `mcp__github__*` keep working.
- **stdio upstream.** The proxy spawns `<real server command>` as a child process with the client's environment passed through unchanged. Two tasks relay newline-delimited JSON-RPC between the client and the child.
- **Streamable HTTP upstream** (`--url`). The proxy is a stdio server to the client and an HTTP client to the upstream, using the `mcp` SDK's HTTP transport. It buffers SSE responses until the final result arrives.
- **Configuring a client.** `tainttrap install mcp --client claude-code|cursor|vscode [--config PATH]` rewrites each server entry so that the proxy launches the original command after `--`. `tainttrap uninstall mcp` restores the original entries. Both commands are idempotent, and the originals are backed up as `*.tainttrap.bak`.

## Relay rules

| Message | Handling |
|---------|----------|
| Discovery, initialization, ping, notifications, `tools/list`, `resources/list`, `prompts/list`, cancellations | Forwarded **byte-for-byte**, so the client and the server agree on the protocol era between themselves (the proxy is era-agnostic). Tool descriptions in `tools/list` are never sent to the core for risk assessment (FR-011). |
| `tools/call` request (client → server) | Held. The proxy sends a `check` request to the daemon, with `adapter: "mcp_proxy"`, `server`, `tool_name`, `arguments`, `call_id: "<server>:<jsonrpc id>"` and the task hints described below. It then acts on the decision. |
| `tools/call`, `resources/read`, `prompts/get` results (server → client) | Forwarded unchanged. A copy goes to the daemon as an `observe` request, which marks the content as untrusted for provenance (FR-006). Observation is asynchronous and never delays the relay. |
| Malformed JSON from either side | Forwarded unchanged and logged. TaintTrap does not validate the protocol. |

## Decision → response

**allow, or any outcome in observe mode.** The request is forwarded unchanged.

**block (enforced).** The request is **not** forwarded (FR-002, SC-009). The proxy replies to the client with a tool *execution* error, which the spec says clients should show to the model:
```json
{"jsonrpc":"2.0","id":<id>,"result":{
  "resultType":"complete",
  "content":[{"type":"text","text":"[TaintTrap] Blocked: <reason>. If the user really wants this, ask them to confirm it explicitly."}],
  "isError":true,
  "_meta":{"tainttrap/decision":{"outcome":"block","reason_codes":["untrusted_recipient","secret_in_args"],"entry_id":"01J…"}}}}
```
When the daemon returns a `hint` (core/advice.py), it replaces the sentence after the reason: for a blocked compound shell command it names the blocked part and the parts that would pass, and for a likely data leak (`secret_in_args`, `untrusted_recipient`) it tells the agent not to ask the user to run the call by hand. A likely leak never gets the "ask them to confirm" advice. The proxy has no channel of its own to the human on a block; MCP clients show the error to the model only.
`resultType` is omitted when the client negotiated a legacy-era protocol, which the proxy detects from the relayed handshake. JSON-RPC `error` responses are used only for TaintTrap's own internal failures under `fail_closed` with `deny`.

**ask (enforced).** The proxy tries the following, in order:
1. **In-band elicitation, if the client declared the `elicitation` capability.**
   - *Modern era:* the proxy returns an `InputRequiredResult` with a form elicitation (`approve` / `deny`, plus the reason and the masked arguments). Its `requestState` is HMAC-signed and binds the tool, an argument digest and an expiry. On the retried call, the proxy verifies the state, removes its own `inputResponses` and state, and forwards the original call if the answer was approve.
   - *Legacy era:* the proxy sends an `elicitation/create` request to the client with ids in its own namespace (`"tt-<ulid>"`) and holds the `tools/call` until the answer arrives.
2. **Otherwise, out-of-band approval in the terminal (FR-024).**
   - The daemon registers a pending approval and shows it to any running `tainttrap approvals` session.
   - The human can also answer with `tainttrap approve <id>` or `tainttrap deny <id>` in any terminal.
   - The proxy holds the call for up to `human.timeout_s`.
3. **Timeout or no channel.** The call is denied with the block-style `isError` result, using the reason `"approval timed out"` (FR-025).

## Task resolution (the user's task)

The proxy resolves the user's task from the first of these sources that exists:
1. `params._meta["tainttrap/task"]` on the `tools/call` request, set by custom agents.
2. `--task-file` or the `TAINTTRAP_TASK` environment variable, for CI and headless agents.
3. The latest task recorded by the Claude Code `UserPromptSubmit` hook for the same working directory, if it was recorded within the last `proxy.task_ttl_min` (default 30) minutes.
4. None. The dossier shows `"(unknown task)"`, and the policy treats `aligned` as unsure, so in protecting modes the call escalates and is never auto-allowed when its risk class is above `read_only`.

A model-callable `set_task` tool is **not** offered, because injected text could set the task.

## Provenance scope

Proxy instances started from the same working directory share one daemon-side **workspace scope**. Data read through server A therefore counts as untrusted when it later appears in arguments sent to server B. Claude Code hook sessions with the same `cwd` are linked to that scope, so cross-adapter flows are also caught.

## Failure handling

- **Daemon unreachable or check timed out:** no rules ran, so `failure_mode` (which is about an unavailable model) does not apply. In `observe` the call is forwarded; in protecting modes it takes the **ask** path (elicitation if the client supports it; otherwise denied, since the daemon's approval queue is down), or is blocked with `fail_closed_action: block`.
- **Upstream server crashed.** The proxy relays EOF, exits with the child's exit code and logs the event.
- **Credentials (FR-033).** Environment variables and HTTP auth headers are passed straight to the upstream. They are never sent to the daemon and never logged; the masker drops `env` and `Authorization` values.

## Claude Code with both adapters installed

The Claude Code `PreToolUse` hook already sees `mcp__*` calls, so in Claude Code the hook is the primary check and the proxy is optional defence in depth. If both are active, the daemon de-duplicates the check: a hook decision for an identical `(tool, argument digest)` in the same workspace within 5 s is reused by the proxy and logged as `dedup_of: <entry_id>`.
