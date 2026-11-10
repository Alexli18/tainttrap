# Data Model: TaintTrap MVP

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md) · **Research**: [research.md](./research.md)

All entities are in-process value objects (Pydantic v2 models, see research R-08) unless marked *persisted*. Persisted data lives under the TaintTrap state directory (`$TAINTTRAP_HOME`, default `~/.tainttrap/`). Config lives under the protected config directory (research R-11).

## Enumerations

| Enum | Values | Notes |
|------|--------|-------|
| `RiskClass` | `read_only`, `write_internal`, `external_communication`, `destructive`, `financial`, `credential_access`, `unknown` | `unknown` applies only to tools missing from the registry (FR-011). The model never outputs it. |
| `Origin` | `user`, `untrusted`, `derived`, `literal` | `user`: matches the user's task text. `untrusted`: matches a fragment of a tool response. `derived`: no match, but produced by the agent. `literal`: a constant or short value that is not matched (below the minimum fragment length). |
| `Outcome` | `allow`, `ask`, `block` | The final verdict. A hook adapter maps `block` to `deny`. |
| `Mode` | `observe`, `soft`, `strict` | Default `observe` (FR-020). |
| `DecidedBy` | `rules`, `model`, `judge`, `human`, `failure_mode`, `policy_default` | The layer that produced the final answer. |
| `FailureMode` | `fail_open`, `fail_closed` | Default `fail_open` (FR-026). |
| `Adapter` | `claude_code_hook`, `mcp_proxy`, `sdk` | Records where the call was intercepted. `sdk` covers every user of the Python client (`tainttrap.client`): the Claude Agent SDK helper, custom agents, and the local Ollama test agent. |

## Core entities

### UserTask
| Field | Type | Rules |
|-------|------|-------|
| `session_id` | str | Required |
| `text` | str | The latest user prompt. Earlier prompts in the session stay in `history`. |
| `history` | list[str] | Up to 5 earlier prompts, newest first. They are used for `user` provenance matching. |
| `source` | enum `hook_prompt` \| `proxy_config` \| `proxy_tool` \| `none` | `none` means the task is unknown: the dossier shows `"(unknown task)"`, and the policy treats a missing task as unsure (research R-04). |
| `updated_at` | datetime (UTC) | |

### ToolCall
| Field | Type | Rules |
|-------|------|-------|
| `call_id` | str | `tool_use_id` from the hook, or the JSON-RPC id from the proxy. Unique within a session. |
| `session_id` | str | |
| `adapter` | Adapter | |
| `tool_name` | str | Normalized: hook MCP names `mcp__<server>__<tool>` become `server` + `tool`. |
| `server` | str \| null | The MCP server name, if any |
| `arguments` | dict[str, Any] | The raw arguments. They are never logged unmasked. |
| `received_at` | datetime | |

### ToolRegistryEntry *(persisted: built-in catalog + user overrides)*
| Field | Type | Rules |
|-------|------|-------|
| `name` | str | The tool name or a glob, for example `Bash`, `github.*` |
| `server` | str \| null | null for built-in agent tools |
| `description` | str | ≤ 300 characters, written by a person, never taken from the MCP server (FR-011) |
| `risk_class` | RiskClass | It cannot be `unknown` |
| `arg_risk_overrides` | list[ArgRule] | Optional. Example: a `Bash` command matching `^rm\s+-rf` → `destructive`. A `git push --force` → `destructive`. |
| `sensitive_args` | list[str] | JSON paths whose values are always masked in the log |
| `source` | enum `builtin` \| `user` | A user entry overrides a built-in one with the same key |
| `output_trust` | enum `first_party` \| `third_party` | Default `third_party`. Who can write the data the tool returns. Only the user's own address book is `first_party`; CRM, inbox, web and repositories are `third_party`, because outsiders can put data there. A recipient that came only from `first_party` tools is asked about instead of blocked (spec FR-021). |

Lookup order: exact user entry → exact built-in → user glob → built-in glob → `unknown`.

### ArgumentProvenance
| Field | Type | Rules |
|-------|------|-------|
| `path` | str | A JSON path into the arguments, for example `args.to`, `args.body` |
| `origin` | Origin | |
| `matched_call_ids` | list[str] | The tool responses the value matched, if `untrusted` |
| `match_kind` | enum `exact` \| `substring` \| `base64` \| `url` \| `case_folded` \| null | |
| `match_len` | int | The length of the longest matched fragment, in characters |

Rule (FR-006): a value is `untrusted` if any normalized fragment of at least `provenance.min_fragment_len` characters (k-gram channel, default k = 24), or an exact match of an extracted entity of at least 6 characters (email addresses, URLs, domains, IP addresses, paths) through the Aho-Corasick channel appears in the untrusted-fragment index for the session (research R-06). When both a `user` match and an `untrusted` match exist, `untrusted` wins only if the fragment is missing from the user's task.

### UntrustedFragmentIndex *(per session, in daemon memory; optionally snapshotted)*
| Field | Type | Rules |
|-------|------|-------|
| `session_id` | str | |
| `entries` | rolling hashes of normalized shingles plus the extracted entities (emails, URLs, domains, paths, long tokens) | Each entry is linked to its `call_id` |
| `max_bytes` | int | Default 8 MB per session. The oldest entries are evicted first (LRU). |
| `ttl` | duration | Default 24 h after the last activity |

### Dossier
The input to the model and the judge. It is serialized to the training format in [contracts/dossier.schema.json](./contracts/dossier.schema.json).

| Field | Type | Rules |
|-------|------|-------|
| `user_task` | str | Shortened to 512 tokens, keeping the start and the end |
| `tool` | str | |
| `tool_description` | str | From the registry only |
| `tool_risk_class` | RiskClass | |
| `args` | dict | Long string values are shortened, keeping the start and the end (FR-008). The truncation markers are `…[truncated N chars]…` |
| `untrusted_fields` | list[str] | The paths whose `origin = untrusted` |
| `user_fields` | list[str] | The paths whose `origin = user` |
| `recent_actions` | list[str] | The last 8 tool names in the session, oldest first |
| `truncated` | bool | Set if any field was shortened |
| `token_estimate` | int | After truncation it MUST be ≤ the device budget: 512 on the CPU INT8 tier, 2048 on GPU tiers (research R-03). Truncation keeps, in priority order: tool, risk class, provenance lists, argument start and end, task, recent actions. |

Invariant: the dossier is built **after** secret detection. The model sees secrets as typed placeholders (for example `<SECRET:aws_access_key>`), never the raw values. This keeps model inputs and logs aligned (research R-05).

### RuleResult
| Field | Type | Rules |
|-------|------|-------|
| `rule_id` | str | For example `secret.aws_access_key`, `domain.deny`, `budget.financial_amount`, `self_protect.config_path` |
| `verdict` | enum `block` \| `ask` \| `allow` \| `none` | `none` means the rule gives no final answer |
| `final` | bool | true: the model is skipped (FR-012) |
| `evidence` | str | Masked |
| `severity` | enum `info` \| `warn` \| `critical` | |

### Assessment (model or judge output)
| Field | Type | Rules |
|-------|------|-------|
| `aligned` | float [0,1] | Calibrated (FR-017). It is the probability of the option "matches task" in a Laya `choice` question with the options matches / does not match / unclear. Laya's yes-or-no `noul` question type is not used here, because it can follow its option labels instead of the input (research R-03). |
| `risk` | RiskClass (no `unknown`) + `risk_probs`: dict[RiskClass, float] | The probabilities sum to 1 |
| `sensitive_data` | float [0,1] | |
| `needs_human` | float [0,1] | |
| `source` | enum `model` \| `judge` | |
| `model_id` | str | For example `tainttrap-laya-en@<sha12>`, or the judge's provider/model |
| `latency_ms` | float | |
| `rationale` | str \| null | Judge only, ≤ 400 characters |

### Policy *(persisted, protected — see [contracts/policy.schema.json](./contracts/policy.schema.json))*
| Field | Type | Default |
|-------|------|---------|
| `version` | int | 1 |
| `mode` | Mode | `observe` |
| `thresholds.aligned_block` | float | 0.2, set after calibration |
| `thresholds.aligned_allow` | float | 0.8 |
| `thresholds.sensitive_block` | float | 0.9 |
| `thresholds.needs_human_ask` | float | 0.7 |
| `risk_actions` | map RiskClass → {`aligned_high`: Outcome, `aligned_mid`: Outcome \| `escalate`} | The table in spec FR-021, mirrored in the policy contract defaults. `escalate` is a policy value, not an Outcome; the mode resolves it (see "Mode semantics"). |
| `rules.secrets.enabled` | bool | true |
| `rules.domains.allow` / `deny` | list[str] | [] / [] |
| `rules.commands.allow` / `deny` | list[regex] | [] / [] |
| `rules.commands.use_builtin_deny` | bool | true. Adds the built-in list of dangerous commands to `deny`. |
| `budgets.per_session` | map RiskClass → int | `financial: 3`, `destructive: 10`, `external_communication: 20` |
| `budgets.max_money_per_session` | {amount: float, currency: str} | {100, "USD"} |
| `failure_mode` | FailureMode | `fail_open` |
| `fail_closed_action` | enum `ask` \| `block` | `ask` |
| `model.timeout_ms` | int | 2000 |
| `judge.enabled` | bool | false |
| `judge.provider` | enum `openai_compatible` \| `anthropic` | — |
| `judge.endpoint` / `judge.model` / `judge.api_key_env` | str | — |
| `judge.timeout_ms` | int | 15000 |
| `human.timeout_s` | int | 60 |
| `human.channel` | enum `terminal` | `terminal` |
| `logging.retain_days` | int | 90 |
| `telemetry` | bool | false. It must stay false in the MVP; the schema rejects `true`. |
| `model.tier` / `model.enabled` | enum `auto` \| `cpu-int8` \| `gpu-fp16` \| `trt-fp16` / bool | `auto` / true. `enabled: false` gives rules plus judge only. |
| `provenance.min_fragment_len` / `min_entity_len` | int | 24 / 6 |
| `hook.explicit_allow` | bool | false |
| `proxy.task_ttl_min` | int | 30 |

[contracts/policy.schema.json](./contracts/policy.schema.json) is the complete, authoritative list of policy keys. This table mirrors it.

Validation (FR-022): `0 ≤ aligned_block < aligned_allow ≤ 1`. If `judge.enabled` is true, `endpoint` and `model` are required. A remote judge endpoint needs `judge.allow_remote: true`, an explicit opt-in (FR-030). Unknown keys are rejected. On error the daemon refuses to start, or keeps the last good policy on reload.

### Decision
| Field | Type | Rules |
|-------|------|-------|
| `call_id` | str | |
| `outcome` | Outcome | What the decision logic chose |
| `enforced` | bool | false in `observe` mode, and for shadow models |
| `effective_outcome` | Outcome | What the adapter actually returned: `allow` when not enforced |
| `decided_by` | DecidedBy | |
| `reason` | str | Plain language, ≤ 300 characters, with no secrets. It is shown to the agent or the human. |
| `reason_codes` | list[str] | Machine-readable, for example `untrusted_recipient`, `secret_in_args`, `task_mismatch`, `budget_exceeded`, `unknown_tool` |
| `escalations` | list[{to: `judge` \| `human`, result, latency_ms}] | |
| `latency_ms` | float | End to end inside the core |

### DecisionLogEntry *(persisted: JSON Lines, see [contracts/log-entry.schema.json](./contracts/log-entry.schema.json))*
`{schema_version, ts, entry_id (ULID), session_id, adapter, mode, policy_hash, model_version, dossier (masked), provenance[], rule_results[], assessment?, judge_assessment?, human?: {answer, latency_s, timed_out}, decision, shadow?: {model_version, outcome}}`

- Append-only. Files are rotated daily as `decisions-YYYY-MM-DD.jsonl` and deleted after `logging.retain_days`.
- Invariant (FR-027, SC-010): before writing, every string goes through the secret masker again, as defence in depth.

### MistakeFlag / RetrainingExample *(persisted: `datasets/flags.jsonl`)*
| Field | Type | Rules |
|-------|------|-------|
| `entry_id` | str | References a DecisionLogEntry |
| `flagged_at` | datetime | |
| `correct_outcome` | Outcome | Required |
| `correct_labels` | {aligned?, risk?, sensitive_data?, needs_human?} | Optional, finer-grained labels |
| `note` | str | Optional |
| `example` | Dossier (masked) + labels in the training JSONL format | Written at flag time, so the dataset stays usable after the log is rotated |

Flagging the same `entry_id` again replaces the earlier flag; this is the last-write-wins rule.

### EvaluationReport *(release artifact: `eval/reports/<model_version>/report.json` + `.md`)*
`{model_version, policy_hash, datasets: [{name, version_sha, n_attack, n_benign, attack_block_rate {value, ci95}, benign_pass_rate {value, ci95}, judge_rate, human_rate, ece, per_class: {...}}], baselines: [{name: rules_only | llm_judge_every_step | <detector>, same metrics}], latency: [{device, p50_ms, p95_ms}], trigger_test: {phrases_tested, flips}, agentdojo_pair: {with: {asr, utility}, without: {asr, utility}}}`

## Decision state machine (per call)

```text
Received ──► DossierBuilt ──► RulesEvaluated ─┬─(final)──────────────────────────────► Decided
                                              └─(no final)─► ModelAssessed ─┬─(confident)─► Decided
                                                   │                        └─(unsure)──► Escalated
                                                   └─(model down/timeout)─► FailureMode ──► Decided | AskHuman
Escalated ─► JudgeAssessed ─┬─(confident)─► Decided
     │                      └─(unsure/error)─► AskHuman
     └─(judge off)──────────────────────────► AskHuman (soft/strict) | Decided(ask, not enforced) (observe)
AskHuman ─► Approved | Denied | TimedOut(=Denied) ─► Decided
Decided ─► Logged ─► Returned to adapter (enforced unless mode=observe)
```

In `observe` mode the pipeline runs fully, except that the judge and the human are **not** contacted. The would-be escalation is recorded as `outcome=ask, enforced=false`, so observe mode adds no latency and no prompts (spec US2).

## Mode semantics (spec FR-020, FR-021; clarified 2026-10-10)

First, the engine computes a **raw outcome**: the final rule verdict if there is one, otherwise the `risk_actions` cell, where `aligned < aligned_block` always gives `block`. The mode then maps that raw outcome to the effective one:

| Raw outcome | `observe` | `soft` | `strict` |
|---|---|---|---|
| `block` from a final rule (`decided_by=rules`) | log only | **block** | **block** |
| `block` because `aligned < aligned_block` | log only | **block** | **block** |
| `block` from the action table (for example `financial` in the unsure band) | log only | **ask** (human) | **block** |
| `escalate` | log only (`ask`, not enforced) | **ask** (human; judge never contacted) | judge → human if the judge is unsure, errors or is off |
| `ask` | log only | ask | ask |
| `allow` | allow | allow | allow |

"Confidently dangerous" (soft mode) means exactly the first two rows.

**Reason text for a final-rule block (US1 AS-1).** When a rule blocks a call and the model is available, the engine also runs the model within the remaining deadline, only to enrich the reason. It adds `task_mismatch` when `aligned < aligned_allow`. The model never changes the decision here, and if it times out the reason simply omits that part.
