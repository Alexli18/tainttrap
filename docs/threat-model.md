# Threat model

TaintTrap checks the tool calls an AI agent is about to make. It judges **actions**, not inputs: it does not scan the documents, web pages or tool output the agent reads for injected text. The attack it targets is prompt injection through data the agent reads (a README, an address book entry, a web page) that steers the agent into a dangerous tool call.

This page lists what TaintTrap looks at and, more importantly, what it does not catch. Measured results are in the README; the sources of the statements below are `PRD.md` and `specs/001-tainttrap-mvp/`.

## What TaintTrap looks at

- **Provenance of arguments.** A value that first appeared in a tool response (not in the user's task) is untrusted. Matching also catches base64-encoded, URL-encoded, partial and case-changed copies.
- **Secrets in arguments.** Rules generated from gitleaks and Betterleaks, applied before any model. Secrets are masked in every log entry.
- **Destinations.** Domain and command allow and deny lists, and recipients a human approved earlier.
- **Risk class from a trusted registry.** Tool descriptions advertised by MCP servers are never used; a tool missing from the registry gets the `unknown` class.
- **Task runners.** `make <target>`, `npm run <script>` and `just <recipe>` are expanded one level at check time.
- **Self-protection.** Agent calls that edit TaintTrap's policy, registry or logs, or stop the daemon, are blocked in `soft` and `strict` mode.

## Not covered

1. **Observe mode never blocks.** It is the default. It only logs.
2. **Manipulation inside a permitted action.** If the agent picks the wrong vendor, or writes a misleading summary, with arguments that look legitimate, TaintTrap has nothing to flag. This is a stated non-goal; use human approval for such decisions.
3. **Indirect attacks beyond one level of task-runner expansion.** A recipe that calls a script that calls another script is not followed further.
4. **No fine-tuned model ships yet.** Until a verified model artifact is installed, the daemon uses a heuristic that judges alignment from argument provenance only. Paraphrased and look-alike cases are the weak spot: on the 10 hard attack cases of the detection benchmark, the rules and heuristic catch 4 (they miss `reversed_key` and `spelled_out_address`).
5. **Clients reached only through the MCP proxy.** There only MCP tool calls are checked. The client's built-in terminal and file editing are not.
6. **Self-protection for shell commands is text matching.** It is a deny-list and can be evaded. The guarantee is a managed install (`--scope managed --disable-bypass`) with the `ConfigChange` hook; a plain user install does not provide it.
7. **Daemon restarts.** The provenance index, observed secrets and per-session tasks live in memory. After a restart, sessions that predate the new daemon run in a degraded mode. Policy, registry, logs and approved recipients are on disk and survive.
8. **An attacker who already controls your user account or root**, outside the agent.
9. **Adaptive attackers.** The detection benchmark and the local-agent scenarios were written by the same person who wrote the defences. They show that the implemented checks work on those cases, not that an attacker who knows the rules cannot get around them.

## Reporting

A new example of something on this list: open a "Known limitation" issue. Something TaintTrap claims to block that gets through: see [SECURITY.md](../SECURITY.md).
