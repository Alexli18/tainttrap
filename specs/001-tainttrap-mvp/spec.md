# Feature Specification: TaintTrap MVP — Local Pre-Execution Check of AI Agent Actions

**Feature Branch**: `001-tainttrap-mvp`

**Created**: 2026-10-10

**Status**: Draft

**Input**: User description: "PRD.md" (TaintTrap PRD, Oct 10, 2026). The PRD defines TaintTrap as a local, fast check of every tool call an AI agent is about to make. The check answers allow, ask or block, based on whether the call matches the user's task, whether its arguments carry secrets, and where each argument came from.

**Scope of this spec**: all P0 items of the PRD (the MVP). P2 items (approvals in Slack or on the web, team dashboard, SSO, centralized team policies) are out of scope.

## Clarifications

### Session 2026-10-10

- Q: How should soft mode differ from strict mode when a call fails the check? → A: **Soft** blocks only "confidently dangerous" calls. A call counts as confidently dangerous when a deterministic rule decided to block it (a secret going out, a deny list, self-protection) or the model's aligned confidence is below the block threshold. Every other would-be block becomes "ask a human", and the judge is not used. **Strict** applies blocks as they are and sends unsure calls to the judge, then to a human.
- Q: What should the default policy do with a call that matches the task but belongs to a risky class, and with a call in the unsure confidence band? → A: A per-risk-class action table decides. When a call matches the task, read_only, write_internal and external_communication are allowed, while destructive, financial, credential_access and unknown are asked about. When a call is unsure, read_only is allowed, financial and credential_access are blocked, and the rest are escalated (see FR-021).
- Q: Should the "untrusted recipient in an external action" block also fire when the agent only opens or downloads a URL it found in content, without sending anything? → A: No. A rule blocks a call only when data goes out to an untrusted destination: an addressee, a request body, an upload, a form, a POST, PUT or PATCH request, `curl` data flags, or a secret in the arguments. A read-only fetch of an untrusted URL is left to the model and the policy.
- Q: In a standard install without admin rights, what does "the agent cannot disable protection" promise? → A: Two tiers. A standard install blocks tampering attempts made through agent tools and detects and reports any other tampering; the documentation states plainly that it does not prevent it. An opt-in hardened install (admin rights, a dedicated service account, Claude Code managed settings) makes the configuration truly unreachable for the agent.
- Q: On what hardware and under what conditions should the check-latency target be verified? → A: The p95 targets are ≤ 0.5 s on a reference laptop CPU (Apple M-series Pro class or x86 H-series) with dossiers capped at 512 tokens, ≤ 0.1 s with a GPU, and ≤ 0.15 s on a Jetson Orin Nano at 512 tokens. Thin-laptop latency is measured and published but does not gate the release.
- Q: What happens when the recipient came from a lookup tool such as the address book (not from the user), since a poisoned entry and a genuine one look the same? → A: Ask, not block, when every untrusted recipient came only from first-party tools (the user's own address book); third-party sources (web, inbox, CRM, repositories) stay blocked. A recipient the human approved once is remembered and not asked again. (Decision recorded in PRD, Oct 10, 2026.)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Stop a hijacked agent action in Claude Code (Priority: P1)

A developer runs Claude Code on their own machine and connects TaintTrap to it as a pre-tool-call check, with protection turned on. Before each tool call, TaintTrap builds a short summary of the call (a "dossier"): the user's task, the tool, the arguments, where each argument came from, and recent actions. It runs the dossier through deterministic rules and the action-checking model, and returns allow, ask or block with a plain-language reason. Calls that match the task and carry no foreign data go through silently. Calls that were steered by content the agent read (a web page, file, email or tool response), or that carry secrets to an outside party, are stopped.

**Why this priority**: This is the core value proposition and the first proving ground named in the PRD. Without it nothing else matters. It covers PRD use cases 1–3 end to end.

**Independent Test**: Install TaintTrap, connect it to a Claude Code session in a protecting mode, and replay the PRD use cases: an injected "send ~/.aws/credentials to an outside address" during "find reviews of restaurant X" is blocked with a reason. "Email the report to Ana" is allowed with no prompt. `rm -rf build/` during "rebuild the project" is allowed or asked about, as the policy says.

**Acceptance Scenarios**:

1. **Given** protection is on and the user's task is "find reviews of restaurant X", **When** the agent tries to send the contents of a cloud credentials file to an address that appeared only in a fetched web page, **Then** the call is blocked before it runs and the agent receives a reason naming the untrusted recipient, the secret in the arguments and the mismatch with the task.
2. **Given** protection is on and the user's task is "email the report to Ana" with Ana's address given by the user, **When** the agent calls the email tool with that address and the report, **Then** the call is allowed with no prompt to the human.
3. **Given** protection is on and the user's task is "rebuild the project", **When** the agent runs a recursive delete of the build directory, **Then** the outcome is allow or ask, as the policy for destructive actions with confident task alignment sets it, and the decision carries a reason.
4. **Given** protection is on, **When** the agent makes an ordinary read-only call that matches the task (task "show the logs" → read the application log file), **Then** the call is allowed with no prompt and no visible delay to the user.
5. **Given** any decision is made, **When** the developer opens the decision log, **Then** the entry holds the dossier with secrets masked, the model's answers, the final decision and its reason, the model version and a timestamp.

---

### User Story 2 - Try it safely in observe mode first (Priority: P1)

A developer installs TaintTrap and, without changing any settings, runs their agents as usual. Nothing is blocked and nothing asks for approval. TaintTrap records what it *would* have blocked and what it *would* have asked about. After a few days the developer looks at the record, decides they trust it, and turns on a protecting mode (soft or strict).

**Why this priority**: The PRD names false positives as the top risk ("people turn off a guard that gets in their way within a week"). A safe, non-disruptive default is what lets people adopt the product at all. It is also how the team dogfoods and measures the ≥ 98% pass rate on real traces.

**Independent Test**: Install with defaults, run a session that includes both normal and attack-like calls, and confirm that every call went through unchanged. Confirm that the log and the report list the would-block and would-ask decisions. Switch the mode and confirm that enforcement starts.

**Acceptance Scenarios**:

1. **Given** a fresh install with no configuration changes, **When** the agent makes a call that would be blocked in a protecting mode, **Then** the call goes through, the human is not prompted, and the log records it as "would block" with the reason.
2. **Given** observe mode, **When** the developer runs the report, **Then** they see how many calls were checked and how many would have been blocked, asked about or sent to the judge.
3. **Given** observe mode, **When** the developer changes the policy to soft mode, **Then** from the next call on, confidently dangerous calls are blocked: a deterministic rule decided to block them, or their aligned confidence is below the block threshold. Every other failing call goes to a human, and the judge is not contacted.
4. **Given** strict mode, **When** a call fails the check, **Then** it is blocked. Calls the model is unsure about go to the LLM judge, and then to a human if the judge is also unsure.

---

### User Story 3 - Protect any MCP-based agent without code changes (Priority: P2)

A developer whose agent (Cursor, a custom agent, or any MCP client) talks to tools through MCP servers puts TaintTrap in between as a proxy. They start the proxy with one command and point the agent at it. Every tool call is checked before it reaches the real server. Blocked calls never reach the server, and the agent receives an error with a clear reason, so it can tell the user or try another way.

**Why this priority**: This is the second adapter in the MVP and the one that makes TaintTrap agent-agnostic. It is P2 here only because the hook in Story 1 proves the core first. The PRD makes both adapters P0 for release.

**Independent Test**: Run the proxy in front of a test MCP server, send it allowed and to-be-blocked calls from an MCP client, and confirm that allowed calls reach the server with unchanged results while blocked calls never arrive and the client gets a reasoned error.

**Acceptance Scenarios**:

1. **Given** the proxy in a protecting mode in front of an MCP server, **When** the agent issues a call that the check blocks, **Then** the server never receives the call and the agent receives an error with a plain reason.
2. **Given** the proxy, **When** the agent issues an allowed call, **Then** the call reaches the server and the agent gets the server's response unchanged.
3. **Given** the proxy, **When** an MCP server advertises its own tool descriptions, **Then** TaintTrap ignores them for risk assessment and uses only the trusted tool registry.
4. **Given** the proxy, **When** a server's response contains values (addresses, URLs, file paths, text), **Then** those values are recorded as untrusted, and a later argument that matches one of them is labeled untrusted.

---

### User Story 4 - Escalate unsure calls to an LLM judge and to a human (Priority: P2)

When the local model is not confident, the call goes to a second opinion: an LLM judge the user has explicitly turned on, either a local model or a remote one. If the judge is also unsure, or the policy says so, a human is asked in the terminal to approve or deny, and sees the task, the action and the reason for asking.

**Why this priority**: Calibrated escalation lets the product hit both bars at once: it blocks attacks and does not nag on normal work. It covers PRD use case 4. The core still works without it (Stories 1–3), so it comes after them.

**Independent Test**: Configure thresholds so that a known borderline call falls in the "unsure" band. Confirm that it goes to the judge when the judge is on, and to a human prompt when the judge is off or also unsure. Confirm that the human's answer is applied and logged.

**Acceptance Scenarios**:

1. **Given** strict mode with the judge on, **When** the model's task-alignment confidence falls in the policy's unsure band, **Then** the call goes to the judge and the judge's answer is used and logged.
2. **Given** the judge is unsure or off, **When** a call needs escalation, **Then** the human is prompted in the terminal with the task, the action and the reason, and their approve or deny is applied and logged.
3. **Given** the judge is off (the default), **When** any check runs, **Then** no dossier or log data leaves the machine.
4. **Given** a human prompt is open, **When** nobody answers within the configured timeout, **Then** the call is denied and the outcome is logged as "no response".

---

### User Story 5 - Weekly review: report and flag mistakes (Priority: P3)

Once a week the developer runs a report: what was checked, blocked, asked about, sent to the judge, and flagged as wrong. They go through the decisions and flag the ones that were wrong. Each flagged decision becomes an example in a local dataset that can later be used to retrain the model.

**Why this priority**: This closes the feedback loop (PRD use case 5) and feeds the retraining process. It adds value only once Stories 1–2 produce decisions.

**Independent Test**: Generate a log with a mix of decisions, run the report and check its counts against the log. Flag a decision as wrong and confirm that a corrected example appears in the local retraining dataset.

**Acceptance Scenarios**:

1. **Given** a decision log, **When** the developer runs the report for a time period, **Then** they see the counts of checked, allowed, blocked, asked, sent-to-judge and flagged decisions, with a breakdown per risk class.
2. **Given** a logged decision, **When** the developer flags it as wrong and gives the correct outcome, **Then** a corrected example (dossier with secrets masked, plus the correct label) is added to the local retraining dataset, and the report counts it as a flagged mistake.

---

### User Story 6 - Tune policy and the tool registry (Priority: P3)

A security engineer or advanced developer edits a human-readable policy file: mode, confidence thresholds, the action for each risk class, secret patterns, allow and deny lists for domains and commands, budgets, behaviour when the model is down, and the human-prompt timeout. They also add descriptions and risk classes for in-house tools that the built-in catalog doesn't know. The agent cannot change any of this through its own tools.

**Why this priority**: The defaults must work for the first user without any setup. Tuning matters to teams and security engineers, the later paying audience.

**Independent Test**: Change a threshold and a domain deny list, then confirm that the same call now gets a different decision. Add a custom tool to the registry and confirm that its risk class appears in dossiers. Have the agent try to edit the policy or stop TaintTrap through its tools, and confirm that the attempt is blocked.

**Acceptance Scenarios**:

1. **Given** a domain on the deny list, **When** the agent calls any tool with that domain in its arguments, **Then** the rules block the call without waiting for the model.
2. **Given** a user-supplied tool description with a risk class, **When** the agent calls that tool, **Then** the dossier uses the user-supplied risk class.
3. **Given** a protecting mode, **When** the agent tries to change, delete or bypass the policy or stop TaintTrap through its own tools, **Then** the attempt is blocked and logged.
4. **Given** an invalid policy file, **When** TaintTrap starts, **Then** it refuses to start with that policy, reports the exact problem, and never silently falls back to a weaker setting.

---

### User Story 7 - Trust the published quality numbers (Priority: P2)

A security engineer or a gateway or framework developer evaluating TaintTrap reads the release report. It gives the block rate, the pass rate on normal actions and the share sent to the judge, separately for each benchmark, with confidence intervals and comparisons to the baselines. They can reproduce the numbers from the published method.

**Why this priority**: Honest, published false-positive numbers are the main differentiator in the PRD and a release gate. Without them the product does not ship.

**Independent Test**: Run the published evaluation procedure on the held-out test sets and confirm that the numbers match the report within the stated confidence intervals.

**Acceptance Scenarios**:

1. **Given** a release candidate, **When** the evaluation runs, **Then** it reports each metric separately for the in-house test set and for each held-out open benchmark, with 95% confidence intervals and against three baselines: rules only, an LLM judge on every step, and existing open detectors where they apply.
2. **Given** a release candidate, **When** the hidden-trigger test runs, **Then** no harmless phrase added to a dossier flips a block or ask decision to allow.
3. **Given** a release candidate, **When** the paired agent run is performed (an agent with and without TaintTrap on the same benchmark), **Then** the report includes attack success and task completion for both runs.

---

### Edge Cases

- **Model unavailable, crashed or timed out**: the configured failure mode applies. Fail-open allows the call and logs it. Fail-closed asks a human. The event is logged either way, and the agent never hangs indefinitely.
- **LLM judge unreachable or erroring**: the call is treated as still unsure and goes to a human in protecting modes. It is logged in observe mode.
- **Strict mode with the judge turned off**: unsure calls go to a human instead of the judge.
- **Dossier longer than the model can read** (long email bodies, file contents): long arguments are shortened, keeping the start and the end, so the decision is still made. The shortening is recorded in the log.
- **Transformed untrusted values**: an argument holds a value from a tool response that has been base64-encoded, URL-encoded, partly copied or changed in case. Exact and simple transformed matches are labeled untrusted. Transformations that are not caught are documented as known limits.
- **Secret look-alikes**: hashes, UUIDs and random identifiers that resemble keys must not trigger the secret rule.
- **Tool not in the trusted registry**: it gets an "unknown" risk class, which the policy treats conservatively by default (ask in soft and strict modes).
- **Poisoned tool descriptions from an MCP server**: never used, whatever the server advertises.
- **Fetching a URL found in content**: a read-only download of an untrusted URL, such as a `curl` of a link from a README, is not blocked by rules. The model and the action table judge it. If the same command sends data or a secret to that URL, the rules block it.
- **Bypass around the proxy**: the agent uses a shell command (for example a command-line HTTP client) to reach a destination it could not reach through the proxy. In clients with the pre-tool-call hook (Claude Code and the Claude Agent SDK), the hook checks shell calls as well, so the network action is still checked. In clients that TaintTrap reaches only through the MCP proxy (for example Cursor or VS Code), the client's built-in tools, such as its terminal and file editing, are **not** checked. This is a documented limit (see Assumptions).
- **Agent attacks the guard**: an attempt to edit the policy, delete the log, change the registry or kill the TaintTrap process through agent tools is blocked in protecting modes. In a standard install, tampering through other means, such as a script the agent writes and runs, is detected and reported but not prevented. In a hardened install, the policy is unwritable by the agent's user account.
- **Human not at the terminal**: the approval prompt times out and the call is denied.
- **Several tool calls at once**: each call is checked and decided on its own, with its own log entry. Approval prompts appear one at a time.
- **Manipulation within permitted actions** (the agent picks the "wrong" vendor in a task that allows payments): explicitly not caught. This is documented as a known limit, and human approval is recommended for such decisions.

## Requirements *(mandatory)*

### Functional Requirements

**Interception adapters**

- **FR-001**: The system MUST provide an MCP proxy that intercepts every tool call between an agent and its MCP servers and checks it before the call reaches the server. *(PRD FR-1)*
- **FR-002**: When the proxy blocks a call, the system MUST NOT forward it to the server and MUST return an error to the agent with a plain-language reason. *(PRD FR-1)*
- **FR-003**: The system MUST provide a Claude Code pre-tool-call hook that returns allow, deny or ask, with a reason, for every tool call, including shell commands. *(PRD FR-2)*
- **FR-004**: The decision logic (dossier, rules, model, policy) MUST work the same no matter which adapter intercepted the call. Adapters only translate between the agent and the core.

**Dossier and provenance**

- **FR-005**: For every intercepted call, the system MUST build a dossier: the user's task, the tool and its risk class from the trusted registry, the arguments, the provenance of each argument, and the recent actions in the session. *(PRD FR-3)*
- **FR-006**: The system MUST record values seen in tool responses as untrusted, and MUST label as untrusted any argument that matches a fragment of an untrusted response. This includes simple encodings (base64, URL encoding), partial matches and case changes. *(PRD FR-4)*
- **FR-007**: Values that come from the user's own request MUST be labeled as user-provided (trusted).
- **FR-008**: When a dossier exceeds the length budget of the device it runs on, the system MUST shorten long arguments while keeping their start and end, and MUST record that it did so. The budget is 512 tokens on CPU and up to 2048 on GPU.

**Tool registry**

- **FR-009**: The system MUST ship a built-in catalog of popular tools and MCP servers, each with a trusted description and a risk class: read_only, write_internal, external_communication, destructive, financial or credential_access. *(PRD FR-11)*
- **FR-010**: Users MUST be able to add descriptions and risk classes for their own tools. *(PRD FR-11)*
- **FR-011**: The system MUST NOT use tool descriptions advertised by MCP servers for risk assessment. Tools missing from the registry MUST get an "unknown" risk class. *(PRD NFR-9)*

**Rules engine**

- **FR-012**: Deterministic rules MUST run before the model and MUST be able to give a final decision without it. *(PRD FR-5, NFR-3)*
- **FR-013**: Rules MUST detect common secret formats in arguments (cloud provider keys, access tokens for popular services, private keys) and MUST NOT flag common look-alikes (hashes, UUIDs). *(PRD FR-5)*
  Rules MUST also treat a reference to a known credential file in the arguments of an external action (for example `~/.aws/credentials`, `~/.ssh/id_*`, `.env` files, `~/.netrc`, `~/.kube/config`, `~/.docker/config.json`, cloud CLI credential files) as secret data being sent. A command like `curl -T ~/.aws/credentials …` counts the same as sending the key itself.
- **FR-014**: Rules MUST support allow and deny lists for domains and for commands. *(PRD FR-5)*
- **FR-015**: Rules MUST support budgets: per-session limits on the number of calls of a given risk class and on the total amount of money in financial actions. A call that would exceed a budget MUST be blocked or asked about, as the policy says. *(PRD FR-5)*

**Action-checking model**

- **FR-016**: When the rules give no final answer, the system MUST assess the dossier with a local action-checking model. In one pass, the model returns: the probability that the action matches the user's task (aligned), the action's risk class, the probability that the arguments contain secrets or personal data, and the probability that a human should be asked.
- **FR-017**: The model's probabilities MUST be calibrated on a validation set kept separate from training and test data, so that the policy thresholds mean what they say.
- **FR-018**: The model MUST run entirely on the user's machine.

**Policy and modes**

- **FR-019**: The system MUST read its behaviour from a human-readable policy file. The file sets the mode, the confidence thresholds, the action for each risk class, rule lists, budgets, the failure mode, the judge setting and the human-prompt timeout. *(PRD FR-6)*
- **FR-020**: The system MUST support three modes.
  - **Observe** (the default) logs the would-be outcome and enforces nothing.
  - **Soft** blocks only *confidently dangerous* calls. These are calls that a deterministic rule decided to block, or whose aligned confidence is below the block threshold. Soft mode turns every other would-be block into "ask a human" and never contacts the judge.
  - **Strict** blocks every call that fails the check. It sends unsure calls (aligned confidence in the middle band) to the judge, and to a human if the judge is unsure or turned off.
- **FR-021**: The default policy MUST block a call when aligned confidence is below the lower threshold, or when an untrusted recipient appears in an external-communication action. An *untrusted recipient* is an untrusted destination that data is sent to. It covers an email or message addressee, a request body, a file upload, a form submission, a POST, PUT or PATCH request, `curl` data or upload flags, and any destination that receives a secret. A read-only fetch of an untrusted URL that sends no data is not a recipient. The rules do not block it; the model and the action table decide. Above the lower threshold, the outcome comes from a per-risk-class action table in the policy. The defaults are: Exception: when every untrusted recipient came only from a tool marked first party in the registry (the user's own address book), the call is asked about instead of blocked; recipients the human approved before do not trigger this rule.

  | Risk class | Aligned confidence ≥ upper threshold (matches the task) | Between the thresholds (unsure) |
  |---|---|---|
  | read_only | allow | allow |
  | write_internal | allow | escalate |
  | external_communication | allow | escalate |
  | destructive | ask | escalate |
  | financial | ask | block |
  | credential_access | ask | block |
  | unknown | ask | escalate |

  "Escalate" follows the mode rules in FR-020. The threshold values are set after calibration.
- **FR-022**: The system MUST validate the policy at start-up and refuse to start with an invalid policy, naming the problem.

**Escalation**

- **FR-023**: The system MUST support a pluggable LLM judge for unsure calls, configured as either a local model or a remote service. The judge MUST be off by default and MUST be turnable off. *(PRD FR-7)*
- **FR-024**: The system MUST support human approval in the terminal. The prompt shows the user's task, the action, its arguments with secrets masked, and the reason for asking. The human's approve or deny is applied to the call. *(PRD FR-8)*
- **FR-025**: An approval prompt that gets no answer within the configured timeout MUST resolve to deny.

**Failure handling**

- **FR-026**: The system MUST have a configurable failure mode for when the model or the judge is unavailable or times out. Fail-open (the default) allows the call and logs it. Fail-closed asks a human. *(PRD FR-12)*

**Logging, report and feedback**

- **FR-027**: The system MUST write a structured, machine-readable log entry for every decision. The entry holds the dossier with secrets masked, the rule results, the model's answers, the judge's and the human's answers if any, the final decision and its reason, the mode, the model version and a timestamp. *(PRD FR-9, NFR-5)*
- **FR-028**: The system MUST provide a report command that shows, for a chosen time period, the counts of calls checked, allowed, blocked, asked about, sent to the judge and flagged as mistakes, with a breakdown per risk class. In observe mode it shows the would-be outcomes. *(PRD NFR-16)*
- **FR-029**: The system MUST provide a command to flag a logged decision as wrong and record the correct outcome. The corrected example MUST be added to a local retraining dataset. *(PRD FR-10)*

**Privacy and self-protection**

- **FR-030**: Dossiers and logs MUST NOT leave the user's machine. The only exception is dossiers sent to a remote judge that the user has explicitly turned on. *(PRD NFR-4)*
- **FR-031**: The system MUST send no telemetry by default. *(PRD NFR-6)*
- **FR-032**: In protecting modes, agent tool calls that try to modify policy, registry, log or TaintTrap runtime files, to stop or bypass TaintTrap, or to run any state-changing TaintTrap command (for example approving its own pending request) MUST be blocked. *(PRD NFR-8)*
  - **Standard install** (no admin rights): the system MUST also detect tampering that happens outside agent tool calls: a changed policy, missing hooks or a stopped daemon. It MUST refuse a changed policy until a human confirms it, and it MUST show any gap in protection in the report. The documentation MUST state that this tier detects tampering but does not prevent it.
  - **Hardened install** (admin rights, opt-in): policy, registry and hook configuration MUST be unwritable by the user account the agent runs as.
- **FR-033**: The proxy MUST keep MCP server credentials only as long as it needs them to relay calls and MUST NOT write them to the log. *(PRD NFR-7)*

**Supply chain**

- **FR-034**: The system MUST load model files only in a format that cannot execute code when loaded, and only after checking a pinned version and checksum. *(PRD NFR-10)*
- **FR-035**: The system's own dependencies MUST be pinned to exact versions. *(PRD NFR-13)*

**Model quality and release evaluation**

- **FR-036**: Training and test data MUST be split by tool family and task template, not at random. Test sets MUST never be used for training or for threshold tuning.
- **FR-037**: Open datasets MUST enter training only with clear provenance, a pinned version and a license that allows commercial use. Datasets that fail the license check MAY be used for testing only. *(PRD NFR-11)*
- **FR-038**: Every model release MUST pass a hidden-trigger test: no harmless phrase added to a dossier may flip a block or ask decision to allow. *(PRD NFR-12)*
- **FR-039**: Every release MUST come with a published evaluation report. The report gives each success metric separately for the in-house test set and for each held-out open benchmark, with 95% confidence intervals. It compares the results with three baselines: rules only, an LLM judge on every step, and existing open detectors where they apply. It also includes the paired with-and-without agent run.
- **FR-040**: A new model version MUST be able to run in shadow next to the current one: it logs its own decisions without enforcing them, so the two can be compared before switching.

### Key Entities

- **User Task**: what the human asked the agent to do in the current session. It is the reference point for judging alignment.
- **Tool Call**: one action the agent is about to take: a tool name and its arguments.
- **Tool Registry Entry**: a trusted description of a tool and its risk class. It comes from the built-in catalog or is supplied by the user, never by an MCP server.
- **Provenance Label**: for each argument, whether its value came from the user (trusted) or from a tool response (untrusted).
- **Dossier**: the short, bounded summary of a call that the rules and the model evaluate: the task, the tool, the risk class, the arguments, the provenance labels and the recent actions.
- **Assessment**: the model's answers for a dossier: aligned probability, risk class, sensitive-data probability and needs-human probability.
- **Policy**: the user's configuration of the mode, thresholds, per-risk-class actions, rule lists, budgets, failure mode, judge settings and prompt timeout.
- **Decision**: the final outcome (allow, ask or block, or the would-be outcome in observe mode), with the reason and the deciding layer: rules, model, judge, human or the failure mode.
- **Decision Log Entry**: a persistent record of one decision: the dossier with secrets masked, all layer outputs, the decision, the mode, the model version and a timestamp.
- **Mistake Flag / Retraining Example**: a logged decision the user marked as wrong, with the correct outcome. It is stored in the local retraining dataset.
- **Evaluation Report**: the published per-benchmark metrics, confidence intervals, baseline comparisons and paired agent-run results for a model release.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: At least 90% of unauthorized agent actions are blocked, both on the in-house test set and on each held-out open benchmark, reported separately. *(release gate)*
- **SC-002**: At least 98% of normal actions are allowed without a prompt to the human, measured on at least 750 normal actions from real agent sessions. *(release gate)*
- **SC-003**: No more than 10% of decisions are sent to the LLM judge, on the in-house test set and the held-out benchmarks. *(release gate)*
- **SC-004**: A check adds no more than these times at the 95th percentile:
  - **0.5 s** on a reference laptop CPU (Apple M-series Pro class, or an x86 H-series laptop), with dossiers capped at 512 tokens;
  - **0.1 s** on a laptop or desktop with a GPU;
  - **0.15 s** on a Jetson Orin Nano at 512 tokens.

  Latency on thin-and-light laptops is measured and published, but it does not gate the release.
- **SC-005**: The check uses no more than 1.5 GB of memory while running.
- **SC-006**: In the paired agent run, attack success with TaintTrap is at least 80% lower (relative) than without it, and task completion is no more than 5 percentage points lower.
- **SC-007**: A new user can install TaintTrap and have it checking their agent's calls in observe mode within 10 minutes, with one install command and one start command.
- **SC-008**: 100% of the golden set (30–50 hand-written scenarios with expected decisions) gets the expected decision on every release.
- **SC-009**: In integration testing, 0 blocked calls ever reach the tool server, and 100% of blocked calls return a reason to the agent.
- **SC-010**: 0 secrets appear unmasked in the decision log across the full test suite.
- **SC-011**: 0 hidden-trigger phrases flip a block or ask decision to allow in the pre-release trigger test.
- **SC-012**: Adoption, 3 months after public release: at least 500 GitHub stars and at least 10 teams using TaintTrap in their work.

## Assumptions

- **Scope**: this spec covers the PRD's P0 scope: both adapters, the decision core, the model and its release evaluation, the log, the report and the flag command. Approvals in Slack or on the web, the team dashboard, SSO and centralized team policies are out of scope (PRD P2).
- **Fallback if the model misses the bars**: per the PRD's week-4 decision point, version 1 may ship with rules plus the LLM judge only, and the model comes later. The requirements are written so that the rules and the judge work without the model.
- **Default failure mode** is fail-open. The PRD leaves the default unset but describes fail-closed as "optional", and observe mode is the default anyway.
- **Default human-prompt timeout** is 60 seconds and resolves to deny.
- **Paired-run targets** (SC-006) put numbers on the PRD's "attack success drops; task completion barely changes". The PRD itself gives no numbers for these.
- **Time to first value** (SC-007, 10 minutes) is an assumed target that follows from the PRD's "one install command, one start command".
- **Unknown tools** (not in the registry) are asked about in soft and strict modes by default.
- **Budgets** means per-session limits on call counts per risk class and on total money in financial actions. The default values are set in the default policy.
- **Platforms**: macOS, Linux (x86 and ARM, including Jetson-class edge devices) and Windows through its Linux subsystem.
- **Technology choices named in the PRD** are design inputs for the planning phase, not requirements of this spec. They include: the Laya / ModernBERT-large base model, fine-tuning with a 2048-token context, the model export and quantization format, the language runtime and version, the policy and log file formats, safetensors, and Kaggle for training.
- **Known limit (MCP-only clients)**: when TaintTrap protects a client only through the MCP proxy, only MCP tool calls are checked. Self-protection (FR-032) and shell-bypass protection then depend on the client's own settings, such as turning off or restricting its built-in terminal. The documentation says so, and approvals use an out-of-band confirmation code, so an agent can't approve its own requests.
- **Known limit**: manipulation within permitted actions is not detected. The documentation will say so and recommend human approval for important decisions.
- **First test target**: the earliest end-to-end testing uses a local agent driven by an open model on Ollama (`qwen3:4b`), in a sandbox with fake email, web and network tools, connected through the custom-agent integration. Claude Code testing follows. This changes the order of validation, not the scope.
- **Dependencies**: Ollama with an open model, for the first local tests; the Laya base model and training notebook; the MCP protocol; Claude Code's pre-tool-call hook; the licenses of the open datasets; and access to LLM assistants for generating and reviewing synthetic data.
- **Open business questions** from the PRD (final name, core license, business registration, beta users) do not affect the functional behaviour specified here. They are tracked outside this spec.
