---
name: decision-records
description: Record TaintTrap design decisions as numbered decision records in docs/design/decisions/, with the security and false-positive consequences of each choice, and answer "why is it built this way?" from them. Use when a trade-off is settled, when the user says "record this decision", or when someone asks why TaintTrap behaves a certain way.
---

# TaintTrap decision records

Adapted from the `architecture-decision-records` skill of [ECC](https://github.com/affaan-m/ECC) (MIT), with two sections added that every TaintTrap decision has: what it does to attacks and what it does to false positives.

Security reviewers and contributors will ask "why does it ask here instead of blocking?" or "why trust the address book?". A short record answers that once, with the alternatives that were rejected.

## Where

```
docs/design/decisions/
  README.md                 index
  0001-check-actions-not-text.md
  ...
  template.md
```

## Format

```markdown
# NNNN: <decision in a few words>

**Date:** YYYY-MM-DD (for a backfilled record: the date the decision was made, plus "recorded YYYY-MM-DD")
**Status:** proposed | accepted | superseded by NNNN | deprecated

## Context
2-5 sentences: the problem, the constraints, what forced a choice.

## Decision
1-3 sentences, present tense: "TaintTrap asks when ...".

## Alternatives considered
- **<alternative>** - why not, in one or two sentences.

## Security consequences
Which attacks this stops, which it leaves open, and where that gap is documented.

## False-positive consequences
What normal work now gets a question or a block, and how often (benchmark or trace numbers when available).

## Revisit when
The evidence that would reopen this decision, e.g. "the trained classifier reaches X on the hard variants".
```

Keep each record readable in two minutes. Context longer than ten lines means it is two decisions.

## Workflow

1. **Detect.** A trade-off was settled in conversation, a review, or `research.md` ("we decided", "instead of", "the reason is").
2. **Draft** the record and show it to the user. Write nothing until they approve. If `docs/design/decisions/` does not exist, ask before creating it with `README.md` and `template.md`.
3. **Number** it: next free number in the directory.
4. **Index** it in `README.md`: `| [NNNN](NNNN-title.md) | Title | Status | Date |`.
5. **Supersede, never edit history.** When a decision changes, write a new record and mark the old one `superseded by NNNN`.

When asked "why does TaintTrap do X?", search the index and records first. If none covers it, say so and offer to record one.

## Backlog: decisions already made

These were settled during development and are worth backfilling first. Check each against the code and `research.md` before writing; the summaries below are starting points, not the record.

1. Check the consequence (the tool call), not the cause (the injected text).
2. Observe mode is the default; protection is switched on deliberately.
3. An address from the user's own address book leads to a question; one from CRM, inbox, web or a repository leads to a block (`output_trust`).
4. Recipients are remembered only after an explicit approval with the dialog code, per tool; "the tool ran after ask" teaches nothing.
5. Approval codes are shown only in a system dialog; without a display, approvals and policy reloads through the daemon are refused.
6. In `bypassPermissions`, the hook never returns "ask"; it waits for approval in TaintTrap's own queue.
7. The installer always sets `onFailure: "block"`; `failure_mode` covers only an unavailable semantic check; an unreachable daemon means ask or block outside observe.
8. A compound command is decided as a whole; per-part analysis is used only to tell the agent which part was blocked.
9. `make`, `npm run` and `just` targets are expanded one level at check time, accepting the edit-before-run race.
10. Copies of sensitive files are tracked in daemon memory for the session; an upload of any local file to a host not named in the task is at least a question.
11. Self-protection rules are a defence layer; managed Claude Code settings are the guarantee.
12. Open: English or multilingual base model for the classifier.
13. Open: project license.
