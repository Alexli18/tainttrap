---
name: security-self-audit
description: Audit TaintTrap's own attack surface - hook and proxy input, daemon sockets, approval codes, state files, secrets held in memory, logs, policy sources and regexes run on attacker text - and turn each gap into a failing test. Use before a release, after changing the daemon, hook client, proxy, approvals or policy loading, or when asked "is TaintTrap itself safe?".
---

# TaintTrap security self-audit

Adapted from the `agent-security-hardening` skill of [ECC](https://github.com/affaan-m/ECC) (MIT) and mapped onto TaintTrap's boundaries. Some checks come from how ECC's own hook runtime fails closed.

A guard is attacked differently from the agent it guards. The attacker controls the text of tool calls and tool output, and the agent runs as the same OS user as TaintTrap. Every check below assumes both.

The result of this audit is tests, not a checklist. A finding is closed when a test exercises it through the real entry point (hook client, MCP proxy, sockets) and fails before the fix.

## 1. Map the boundaries

Write the map before checking anything, as `source -> parser -> validator -> effect`. For TaintTrap it includes at least:

| Source | Entry point | Effect |
| --- | --- | --- |
| Claude Code tool call (JSON on stdin) | hook client | allow / ask / deny returned to Claude Code |
| MCP client request | MCP proxy | forwarded to the server or refused |
| Any same-user process | `check.sock`, `admin.sock` | decisions, approvals, policy reload, recipients |
| Human | system dialog code, real terminal | approvals, remembered recipients |
| Files | policy, `hook.json`, `approved_recipients.json`, logs, Claude Code settings | behaviour on next check or next session |
| LLM judge response | judge client | verdict on uncertain calls |
| Installer | Claude Code settings files | which hooks run, `onFailure`, timeouts |

For each effect, name the one validator that runs immediately before it. An effect with no named validator is a finding.

## 2. Same-user commands

The agent's shell runs as the same user, so file permissions on sockets do not separate it from the human. Enumerate every command accepted on `check.sock` and `admin.sock` and classify it:

- **read-only** (status, report, list) - fine for any caller;
- **weakens protection** (approve, remember a recipient, reload or change policy, disable, change mode) - must require proof that a human acted: the code from the system dialog, a real terminal, or both. A same-user process that can call it without that proof is a bypass.

Test: from a subprocess with no terminal and no dialog, call each weakening command and assert it is refused and nothing changed.

## 3. Input bounds

- Rules must see the **whole** argument. Truncation keeping the start and end is acceptable only for the semantic model's input. An attacker can pad a command to several megabytes and put `curl -T .env ...` in the middle.
- Define a hard maximum input size. Above it, do not truncate and decide: outside observe mode, ask or block. ECC's hook runner fails closed for exactly this reason.
- Test: a 2 MB command with an upload in the middle is blocked in soft and strict modes.

## 4. Regexes on attacker text

Rules run regular expressions on text the attacker wrote. A pattern with catastrophic backtracking turns one tool call into a hung hook: blocked if `onFailure` is set, but the agent is stuck, and a fail-open path anywhere becomes a bypass.

- List every pattern applied to tool input or tool output, including user-configurable ones (domain lists, custom rules).
- Flag nested quantifiers and overlapping alternations, or switch hot paths to a linear-time engine (for example `google-re2`).
- Test each pattern against adversarial input sized at the input cap, with a time budget (ECC uses 25 ms per evaluation).

## 5. Policy sources

A repository the agent opens is attacker-controlled. ECC disables repository-tracked hook rules by default for this reason.

- List every place TaintTrap reads configuration from. Configuration inside the project directory, if supported at all, may only tighten the user's policy, never loosen it (no new allowed domains, no lower mode, no disabled rules).
- Unknown keys, unknown mode names and malformed values must fail validation, not fall back to a permissive default.
- Test: a malicious repository with a project-level config that allows `evil.example` does not change any decision.

## 6. Fail closed

Pair this with the `fail-open-hunter` agent. Through the real entry points, each of these must end in ask or block outside observe mode, never in a silent allow:

- daemon not running, socket missing, socket timeout;
- malformed JSON on stdin, unknown tool name, missing fields;
- exception anywhere in rules, dossier building or the semantic check;
- judge timeout, judge error, judge returning unparseable output;
- log write failure, disk full, state file unreadable or corrupt.

On the Claude Code side this relies on `onFailure: "block"` in the hook settings, which Claude Code honours only from v2.1.295. On older versions a crashed hook is a non-blocking error and a hung hook is let through after the default 600-second timeout. `tainttrap doctor` should check the Claude Code version and warn below that release.

## 7. Secrets

TaintTrap holds secrets it has seen in tool output so it can recognise them later. That store is a new target.

- **Redact before emitting.** Use a sentinel secret and assert it is absent from every channel: log files, socket replies, exception text, judge prompts, `tainttrap report` output, and the **block reason returned to the agent**. The reason goes straight into the agent's context and the session transcript.
- The store is memory-only, bounded in size, scoped to the session, and cleared at session end. Test that flooding it with junk does not evict a real secret silently.
- No socket reply reveals whether a given value is a known secret (that turns the daemon into an oracle).

## 8. Files

- State directory `0700`, files `0600`, created atomically with unpredictable temporary names.
- Open state files without following symlinks and check the owner after opening. Test: replace `approved_recipients.json` with a symlink to an attacker-controlled file; TaintTrap refuses to read it.
- Writes to Claude Code settings by the installer are the only legitimate writes to those files; everything else is blocked by self-protection.

## 9. Network

- Without the LLM judge, no outbound connection (the existing test covers this; keep it).
- With the judge: endpoint only from the user's policy, HTTPS with certificate verification for remote endpoints, no credentials forwarded across redirects, bounded response size, and the judge's answer treated as untrusted input.

## Verification gate

Report each check as:

```
<check>: PASS | GAP
  entry point: <hook client / proxy / socket command>
  test: <path::name>, fails before fix: yes/no
  evidence: <command run, exit status, observed absence of the effect>
```

Mock-only tests do not prove file permissions, symlink handling, socket peer behaviour or network egress. At least one test per section must use the real process and the real filesystem.
