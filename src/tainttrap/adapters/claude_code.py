"""Claude Code hook adapter (contracts/claude-code-hook.md).

The mapping functions live in `tainttrap.hookclient` so the hook process stays import-free;
this module re-exports them for the daemon side and for tests.
"""

from tainttrap.hookclient import (
    decision_to_output,
    failure_output,
    hook_output,
    split_tool_name,
)

__all__ = ["decision_to_output", "failure_output", "hook_output", "split_tool_name"]
