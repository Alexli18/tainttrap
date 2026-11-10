# Contract: Command-line interface

TaintTrap installs two entry points:
- **`tainttrap`** is the admin CLI, built on Click. It is only for humans.
- **`tainttrap-hook`** is the hook client. It uses the standard library only, and Claude Code invokes it (see [claude-code-hook.md](./claude-code-hook.md)).

All admin commands accept `--json` for machine-readable output. Exit codes: 0 means ok, 1 means a usage or validation error, 2 means the daemon is unavailable.

## Setup and lifecycle

| Command | Behaviour | Requirements |
|---------|-----------|--------------|
| `tainttrap init` | Writes the default policy (mode `observe`) and the registry overrides file to the config directory, and pulls the pinned model through `model pull`. It is idempotent and never overwrites an existing policy. | SC-007 |
| `tainttrap install claude-code [--scope user\|project\|managed] [--lock-hooks] [--dry-run]` | Adds the hook entries. It prints a diff and asks for confirmation. `managed` needs sudo and also writes `permissions.deny` for the protected paths. | FR-003, FR-032 |
| `tainttrap install mcp --client claude-code\|cursor\|vscode [--config PATH] [--server NAME…] [--dry-run]` | Wraps the selected servers with `tainttrap run` and backs up the original file. | FR-001 |
| `tainttrap uninstall claude-code\|mcp …` | Restores the original entries. | |
| `sudo tainttrap install --system` | Hardened mode: creates the service user, the root-owned config and the system service. | R-11 |
| `tainttrap daemon start\|stop\|status\|reload [--foreground]` | Controls the daemon. `reload` re-validates the policy and registry and needs the out-of-band code; a failed reload keeps the last good policy. `stop` and `shutdown` are admin operations and are logged. | |
| `tainttrap run --server NAME [--url URL] [--task-file PATH] -- CMD…` | Runs the MCP proxy. Clients launch it. | FR-001, NFR-15 |

## Policy, registry and model

| Command | Behaviour |
|---------|-----------|
| `tainttrap policy show` | Prints the effective policy with defaults filled in, and its hash. |
| `tainttrap policy validate [FILE]` | Validates the policy against [policy.schema.json](./policy.schema.json) and the semantic rules (FR-022). It exits 1 and names the bad field. |
| `tainttrap policy mode observe\|soft\|strict` | Edits the policy file, then triggers a `reload`. The reload needs the out-of-band code, which the human types on a TTY (see daemon-api.md). |
| `tainttrap policy apply FILE` | Hardened mode: installs a policy file. Needs sudo. |
| `tainttrap registry list [--unknown]` | Lists the tools and their risk classes. `--unknown` lists tools seen in the logs that are missing from the registry. |
| `tainttrap registry add NAME --risk CLASS --description TEXT [--server S]` | Adds a user override to the registry. |
| `tainttrap model pull [--version V]` | Downloads the model, verifies it against `models.lock` and selects the device tier. |
| `tainttrap model info` | Shows the model version, its sha, the tier (cpu-int8, gpu-fp16 or trt-fp16), the token budget and the calibration date. |
| `tainttrap model shadow enable VERSION\|disable` | Runs a second model in shadow, which logs its decisions without enforcing them (FR-040). |

## Approvals (FR-024)

| Command | Behaviour |
|---------|-----------|
| `tainttrap approvals` | Interactive terminal view of pending approvals, one at a time in FIFO order. For each one it shows the task, the tool, the masked arguments, the reason and a countdown. The human presses `a` or `d`, then types the out-of-band code from the OS notification. It refuses to run without a TTY on stdin and stdout. There is no `--json` form. |
| `tainttrap approve ID` / `tainttrap deny ID` | Answers a single approval. It needs a TTY and the out-of-band code in a standard install, or `sudo` in a hardened install. |

## Review loop (FR-028, FR-029)

| Command | Behaviour |
|---------|-----------|
| `tainttrap report [--since 7d] [--until DATE] [--by risk\|tool\|reason] [--json]` | Counts of calls checked, allowed, blocked, asked about, sent to the judge, sent to a human, timed out and flagged, plus the failure-mode events. In observe mode these are the would-be outcomes. If TaintTrap was disabled during the period, a banner shows the gap (R-11). |
| `tainttrap log [--since …] [--outcome block\|ask\|…] [--tool …] [--limit N]` | Lists the log entries with their `entry_id`. |
| `tainttrap log show ENTRY_ID` | Shows the full entry, with secrets masked. |
| `tainttrap flag ENTRY_ID --correct allow\|ask\|block [--note TEXT] [--labels JSON]` | Writes a MistakeFlag and a RetrainingExample to `datasets/flags.jsonl`. Flagging the same entry again replaces the earlier flag. |
| `tainttrap dataset export [--out FILE]` | Exports the flagged examples in the training JSONL format. |

## Evaluation (development and release only; not part of the user install)

| Command | Behaviour |
|---------|-----------|
| `python -m eval.run --model VERSION --suite all\|<benchmark> [--baselines]` | Writes `eval/reports/<version>/report.{json,md}` (FR-039). |
| `python -m eval.trigger_test --model VERSION` | Runs the hidden-trigger test. Any flip fails the run (FR-038). |
| `python -m eval.latency --model VERSION --tier cpu-int8 [--n 1000]` | Reports p50 and p95 latency on the current device (SC-004). |
