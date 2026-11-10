# Implementation Plan: TaintTrap MVP — Local Pre-Execution Check of AI Agent Actions

**Branch**: `001-tainttrap-mvp` | **Date**: 2026-10-10 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-tainttrap-mvp/spec.md`

## Summary

TaintTrap is a local Python package. It checks each tool call an AI agent is about to make and answers allow, ask or block.

**Components**:
- A resident **daemon** hosts the decision core:
  - a dossier builder with argument provenance;
  - deterministic rules for secrets, domain and command lists, budgets and self-protection;
  - a fine-tuned **Laya** classifier running in ONNX Runtime;
  - a policy engine;
  - optional escalation to an LLM judge and to a human.
- **Two thin adapters** reach the daemon over Unix sockets:
  - **Claude Code hooks**, through a stdlib-only `tainttrap-hook` client;
  - a transparent **MCP JSON-RPC relay proxy**.
- Every decision is logged as masked JSON Lines.
- A report command and a flag command close the retraining loop.

**Separate tracks**: a training and data track (`training/`, run on Kaggle) and an evaluation track (`eval/`). They produce the model and the per-benchmark release report that gates the release.

**Research findings that reshaped the PRD's technical approach** ([research.md](./research.md)):
- The CPU tier must use INT8 with a 512-token dossier cap to have a chance at p95 ≤ 500 ms (R-03).
- Laya decision questions use the `choice` question type, not `noul` (R-03).
- MCP spec 2026-07-28 is session-less, so the proxy is an era-agnostic byte relay (R-02).
- Python's floor moves to 3.11 (R-08).
- In user mode, tamper resistance means detection, not prevention; hardened mode is opt-in (R-11).

## Technical Context

**Language/Version**: Python ≥ 3.11 (CPython 3.11–3.14). On Jetson, use uv-managed CPython 3.12 (R-08).

**Primary Dependencies**:
- **Runtime core:** `pydantic` 2.14, `PyYAML` 6.0.3, `click` 8.5.0, `pyahocorasick` 2.3.1.
- **`[cpu]` extra:** `onnxruntime` 1.31, `tokenizers`, `numpy`.
- **`[gpu]` extra:** `onnxruntime-gpu` (with the Jetson AI Lab index on Jetson).
- **`[http]` extra:** `mcp` 2.3.0.
- **Standard library only:** `asyncio`, `urllib.request` (judge) and `logging`.
- **Training (not shipped):** `laya`, `torch`, `transformers` ≥ 4.48, `huggingface_hub` and `onnx`.

**Storage**: local files only.
- Policy and registry YAML in the config directory.
- JSON Lines decision logs and `datasets/flags.jsonl` under `$TAINTTRAP_HOME`.
- `models.lock` and `datasets.lock` in the repository.
- The in-memory provenance index in the daemon.

**Testing**: `pytest`, plus `pytest-asyncio` for the daemon and the proxy, and `hypothesis` for the matchers. The seven test levels from the PRD map as follows:
- `tests/unit` (level 1, run in CI)
- `tests/golden` (level 2)
- `tests/integration` (level 3, run in CI, with a fake MCP server and a hook harness)
- `eval/` (levels 4 and 5)
- `tests/adversarial` (level 6)
- dogfooding runbook (level 7)

**First end-to-end target (R-13)**: a sandboxed **local agent on Ollama `qwen3:4b`**, protected through the Python client (`src/tainttrap/client.py`). It runs the PRD use cases with and without TaintTrap before any Claude Code session, at no API cost. All of its tools are fakes: an outbox file, a network log and a fixture-backed web.

**Target Platform**: macOS (arm64, x86_64); Linux x86_64 and aarch64, including Jetson Orin Nano on JetPack 6.2; Windows through WSL2.

**Project Type**: a single Python package that provides a CLI, a daemon, a hook client and an MCP proxy, plus non-shipped `training/` and `eval/` workspaces.

**Performance Goals**:
- **Check latency (SC-004):** p95 ≤ 500 ms on the reference laptop CPU (INT8, ≤ 512 tokens); ≤ 100 ms on a desktop or laptop GPU; ≤ 150 ms at 512 tokens on Jetson Orin Nano.
- **Rules path:** ≤ 10 ms end to end.
- **Hook client:** cold start ≤ 40 ms.

**Constraints**:
- Model memory ≤ 1.5 GB (INT8 weights ≈ 0.5 GB).
- No network egress except to a judge the user explicitly enabled.
- No telemetry.
- Models load only from safetensors or a verified ONNX file with a pinned sha256.
- Exact dependency pins.
- Observe mode is the default.

**Scale/Scope**:
- One developer machine, 1–10 concurrent agent sessions, up to about 5 checks per second at peak.
- About 40 functional requirements and 7 user stories.
- A built-in registry of 40–60 tools.
- Dataset v1: 4,000 training and 500 test examples, plus the held-out benchmarks.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

`.specify/memory/constitution.md` is still the **unratified template**: it has no principles, so it imposes no formal gates. Until `/speckit-constitution` runs, the plan is checked against the project's non-negotiables from the PRD and spec, which serve as interim gates:

| Interim gate | Source | Pre-research | Post-design |
|---|---|---|---|
| Core is independent of interception; adapters are thin | PRD "Principle", FR-004 | ✅ | ✅ The daemon protocol ([daemon-api.md](./contracts/daemon-api.md)) is the only entry point to the core. Adapters hold no decision logic. |
| Local only; nothing leaves the machine except an opted-in judge | NFR-4, FR-030 | ✅ | ✅ The judge defaults to off. A remote endpoint needs `allow_remote`. The judge HTTP client is stdlib. No telemetry code path exists (`telemetry` is `const false`). |
| Observe mode is the default | FR-020 | ✅ | ✅ Default policy; `init` never overwrites. |
| Rules run before the model and can decide alone | NFR-3, FR-012 | ✅ | ✅ State machine in [data-model.md](./data-model.md). `model.enabled: false` covers the week-4 fallback. |
| Tool descriptions come only from the trusted registry | NFR-9, FR-011 | ✅ | ✅ The proxy relays `tools/list` without passing descriptions to the core. |
| Secrets masked in logs; credentials never logged | NFR-5, NFR-7 | ✅ | ✅ Masking at dossier build and again at write. The proxy drops env and auth values. |
| Supply chain: safetensors, pinned hashes, pinned dependencies, trigger test | NFR-10–13 | ✅ | ✅ `models.lock`, `datasets.lock`, a hashed `requirements.lock`, `eval.trigger_test` (R-10). |
| The guard cannot be disabled by the agent | NFR-8, FR-032 | ✅ | ✅ Meets the two-tier FR-032 as clarified: `self_protect` blocks every agent tool call that touches the config or runtime or runs a state-changing `tainttrap` command. A standard install also detects other tampering. A hardened install prevents it (R-11). |
| Honest metrics: per-benchmark, with CIs; test sets never used for tuning | FR-036–FR-039 | ✅ | ✅ The `eval/` design and the split guard test (R-12). |

**Result**: PASS. The earlier FR-032 limitation was resolved by the spec clarification of 2026-10-10.

## Spec deviations and amendments

Research produced four amendments. Three were **accepted into spec.md** in the clarification session of 2026-10-10. The fourth deviates from the PRD only. This section is the single source of truth for them; research.md links here.

1. **SC-004 (latency)** — *accepted.* The p95 targets are:
   - ≤ 0.5 s on the reference laptop CPU (Apple M-series Pro class or x86 H-series), with the INT8 model and dossiers of ≤ 512 tokens;
   - ≤ 0.1 s with a GPU;
   - ≤ 0.15 s on Jetson Orin Nano at 512 tokens.

   Thin-laptop latency is published but does not gate the release (R-03).
2. **FR-008 (dossier budget per device)** — *accepted.* The budget is 512 tokens on the CPU tier and up to 2048 on GPU tiers. Training still uses up to 2048 tokens (R-03).
3. **FR-032 (tamper resistance)** — *accepted as two tiers.* A standard install blocks tampering through agent tools, including every state-changing `tainttrap` command, and detects and reports any other tampering. A hardened install prevents it (R-11).
4. **PRD NFR-14 (Python 3.10+)** — *deviation from the PRD only; the spec does not fix a version.* Python ≥ 3.11 (R-08).

The same session also clarified the mode semantics (FR-020), the default action table (FR-021) and the "untrusted recipient" definition (FR-021). data-model.md ("Mode semantics") and tasks.md implement them.

## Project Structure

### Documentation (this feature)

```text
specs/001-tainttrap-mvp/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0: R-01..R-12
├── data-model.md        # Phase 1: entities, enums, decision state machine
├── quickstart.md        # Phase 1: runnable validation scenarios
├── contracts/
│   ├── claude-code-hook.md
│   ├── mcp-proxy.md
│   ├── daemon-api.md
│   ├── cli.md
│   ├── policy.schema.json
│   ├── dossier.schema.json
│   ├── training-record.schema.json
│   └── log-entry.schema.json
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks; not created here)
```

### Source Code (repository root)

```text
pyproject.toml                 # hatchling; extras [cpu] [gpu] [http] [dev]; entry points tainttrap, tainttrap-hook
uv.lock
requirements.lock              # hashed export for verified installs
models.lock                    # pinned HF revisions + sha256 for the base and released models
datasets.lock                  # pinned dataset versions + license + allowed split (train | eval_only)
THIRD_PARTY_NOTICES            # gitleaks / Betterleaks (MIT) rule attribution

src/tainttrap/
├── __init__.py                # import-free (keeps the hook client fast)
├── client.py                  # importable stdlib daemon client (SDK adapter, custom agents, local Ollama agent)
├── hookclient.py              # tainttrap-hook: stdlib only (socket, json, sys, os); failure mode; daemon autostart
├── core/
│   ├── types.py               # Pydantic models from data-model.md
│   ├── dossier.py             # build, truncate to the tier token budget, placeholders
│   ├── provenance.py          # k-gram winnowing index + Aho-Corasick entity channel; decoded variants
│   ├── registry.py            # built-in catalog + user overrides; lookup order; arg-level risk overrides
│   ├── masking.py             # secret placeholders for dossiers, masks for logs
│   ├── rules/
│   │   ├── secrets.py         # vendored rules, (?i) translator, keyword prefilter, entropy, hash/UUID skip
│   │   ├── lists.py           # domain + command allow/deny
│   │   ├── budgets.py         # per-session counts and money
│   │   └── self_protect.py    # config/log/settings paths, stop/uninstall commands
│   ├── model/
│   │   ├── runner.py          # ONNX Runtime session per tier; Laya input packing; batch=1, dynamic length
│   │   ├── calibration.py     # per-head temperatures loaded with the artifact
│   │   └── supply_chain.py    # models.lock verification, offline loading
│   ├── judge/
│   │   ├── base.py            # schema, local re-validation, unsure-on-error
│   │   ├── openai_compat.py
│   │   └── anthropic.py
│   ├── policy.py              # load/validate YAML, thresholds -> outcome, modes, failure mode
│   └── engine.py              # the decision state machine; shadow model
├── daemon/
│   ├── server.py              # asyncio UDS servers (check + admin), peer-cred checks
│   ├── sessions.py            # tasks, recent actions, workspace scopes, budgets
│   ├── approvals.py           # pending approvals, timeouts, confirm codes
│   └── integrity.py           # policy hash pinning, hooks-missing detection
├── adapters/
│   ├── claude_code.py         # hook payload <-> daemon request/decision mapping (used by hookclient)
│   ├── sdk.py                 # Claude Agent SDK PreToolUse callback helper
│   └── mcp_proxy/
│       ├── relay.py           # line relay, tools/call interception, result observation
│       ├── stdio.py           # child-process upstream
│       ├── http.py            # Streamable HTTP upstream via the mcp SDK
│       └── elicitation.py     # MRTR InputRequiredResult + legacy elicitation/create; HMAC requestState
├── logstore/
│   ├── writer.py              # JSONL, masking filter, daily rotation, retention
│   ├── report.py
│   └── flags.py               # MistakeFlag -> RetrainingExample (training-record format)
├── cli/
│   ├── main.py                # click root group and `daemon` commands, per contracts/cli.md
│   ├── install.py             # Claude Code settings + MCP client config rewrite/restore, managed scope, --system
│   ├── init.py  model.py  log.py  policy.py  report.py  run.py  review.py  registry.py
│   └── approvals_tui.py
└── data/
    ├── default-policy.yaml
    ├── registry/*.yaml        # 40-60 built-in tools + popular MCP servers
    └── secrets/rules.toml

tests/
├── unit/                      # level 1: secrets (+ look-alikes), provenance (base64/url/partial/case), policy, dossier
├── golden/                    # level 2: 30-50 YAML scenarios -> expected decision (includes PRD use cases, negation)
├── integration/               # level 3: fake MCP server, hook harness, model crash/timeout, fail-open/closed
├── adversarial/               # level 6: curl bypass via Bash, policy edit, daemon kill, trigger phrases
└── contract/                  # JSON schemas vs Pydantic models; hook I/O fixtures

training/                      # not shipped
├── datagen/                   # tool catalog -> scenarios -> attacks -> hard normals; converters for DTap/ASB/ToolSafety; split.py
├── review/                    # Codex second opinion, disagreement queue, near-duplicate removal
├── data/                      # generated train/validation/test JSONL (not committed if large)
├── notebooks/tainttrap_finetune_2xT4.ipynb   # adapted from the official Laya notebook
└── export/                    # ONNX export, INT8 quantization, TRT profile, per-artifact calibration, parity test vs laya

eval/                          # not shipped
├── adapters/                  # InjecAgent, AgentDojo, A3S-Bench, agent-injection-bench, MCP sets -> dossiers
├── baselines/                 # rules_only, llm_judge_every_step, open detectors
├── data/trigger_phrases.txt
├── local_agent/               # Ollama qwen3:4b test agent: agent.py, tools.py (sandboxed fakes), scenarios/*.yaml, __main__.py
├── run.py  trigger_test.py  latency.py  agentdojo_pair.py
└── reports/<model_version>/
```

**Structure Decision**: a single installable package in a `src/` layout. Everything that must ship lives under `src/tainttrap`, while `training/` and `eval/` are development-only workspaces that share `core/dossier.py` and `core/masking.py`, so the training and inference formats cannot drift. The adapters depend on `core` only through the daemon protocol. The one exception is `adapters/sdk.py`, which may call the daemon client directly.

## Delivery phases (aligned with the PRD milestones)

| Phase | Content | Exit gate |
|---|---|---|
| **P0 – week 1** | Skeleton, daemon, Python client and hook client, rules (secrets, self-protect), provenance, policy (with the mode semantics), observe mode, logging, report. **Local Ollama agent** (`qwen3:4b`) with sandboxed tools and the PRD use-case scenarios. **Latency spike:** export base Laya to ONNX INT8 and measure p95 at 256 and 512 tokens on the reference laptops and on Jetson. | The local agent's injected UC1 never reaches the fake outbox or network in soft mode, while UC2 and "show the logs" complete (rules only). US2 runs end to end. The latency spike decides between Laya-large and the base or multilingual contingency on the CPU tier. |
| **P1 – weeks 2–4** | Data generation and review, a Kaggle fine-tune at 2048, calibration, export and quantization, the model runner, the golden set, the judge and the human paths, the MCP proxy. | **Week-4 decision point:** if the model misses 90% / 98% on the test set, ship v1 with `model.enabled: false` (rules plus judge) and keep training. |
| **P2 – weeks 5–6** | The eval harness on all benchmarks plus baselines, the AgentDojo pair, the trigger test, the adversarial suite, hardened mode, installers. | Release bar: SC-001–SC-003 on the in-house set and on each benchmark, with CIs. |
| **P3 – weeks 6–8** | Dogfooding in observe mode on our own Claude Code agents (≥ 750 normal actions), shadowing, the write-up. | ≥ 98% pass rate on real traces, then the public release. |

## Complexity Tracking

There are no constitution violations to justify, because the constitution is empty. The following choices add complexity deliberately:

| Choice | Why needed | Simpler alternative rejected because |
|---|---|---|
| A resident daemon plus a stdlib hook client | Loading the model takes seconds; the hook spawns a process per call | Loading the model in each hook call would take seconds and break SC-004 |
| A hand-written MCP relay instead of FastMCP | MCP 2026-07-28 and legacy clients coexist; the relay must not translate between eras | The FastMCP proxy is a heavy, fast-churning dependency and rewrites names when aggregating |
| Two device tiers (CPU INT8 at 512, GPU FP16 at 2048) | The CPU latency and memory budget cannot fit FP32 or 2048 tokens | One tier would fail either the CPU latency target or the long-argument recall on GPU |
| A two-channel provenance matcher | Long copies (k-grams) and short sinks such as emails and domains (entities) need different minimum lengths | A single k-gram channel misses short recipients; exact matching alone misses encoded or partial copies |
