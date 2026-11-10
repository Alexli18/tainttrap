# Contributing to TaintTrap

## Running the tests

```bash
uv sync --extra dev --extra data                 # --extra data brings pyarrow, which the held-out set tests need
uv run pytest -q                                  # fast set (default)
uv run pytest -q -m "not model and not ollama"    # full set, with the fail-open audit probes (~4 min)
```

Run the full set before committing a change to the daemon, the hook client or the MCP proxy. CI always runs the full set.

## Test fixtures and fake secrets

TaintTrap's tests contain secret-shaped values on purpose: they are the bait the rules must catch. To keep real secrets out of the repository:

- Use documented example credentials such as `AKIAIOSFODNN7EXAMPLE`, or put `EXAMPLE` or `FAKE` (upper case) inside the value.
- If a test needs a realistic random-looking value, put it in a fixture directory listed in `.gitleaks.toml`, whose README states that every value is fake.
- Use `.example`, `.test` or `.invalid` hosts and `example.com` email addresses.
- Never paste a value from a real `.env`, log or bug report, even one you believe was rotated.

CI scans the tree and the full history with gitleaks. If it flags a fixture, make the value fake; do not widen the allowlist.
