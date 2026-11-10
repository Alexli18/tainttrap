## What changed

<!-- One or two sentences. -->

## Why

<!-- The problem, the issue it fixes, or the decision record it follows. -->

## Checks

- [ ] `uv run pytest`, `uv run ruff check .` and `uv run mypy` pass locally
- [ ] Secret-shaped test values are visibly fake (documented example keys, `EXAMPLE`/`FAKE` inside the value, `.example` hosts), or realistic-looking only inside a documented fixture directory; no real secrets, emails or home paths

## If this changes detection (rules, heuristics, provenance, secret or copy tracking, policy defaults)

- [ ] Each new or changed behaviour has an attack case **and** a benign twin with the same history in the detection benchmark
- [ ] Variants (case, encoding, compound command, copy of the file) are covered, or the gap is recorded as a hard variant
- [ ] Benchmark before/after is in the description: attacks caught, blocked vs asked, benign calls without a question, benign calls blocked
- [ ] "What it catches" / "What it doesn't catch" in the README and the threat model are updated if a guarantee changed

## If this touches the hook client, proxy, daemon, approvals or policy loading

- [ ] Every new error path ends in ask or block outside observe mode, never in a silent allow
- [ ] No new same-user command can approve, disable or loosen anything without the human proof (dialog code, real terminal)
- [ ] Secrets never appear in logs, socket replies, exception text or the reason returned to the agent

## Docs

- [ ] User-facing behaviour changes are reflected in `docs/` and `CHANGELOG.md`
