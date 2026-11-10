import pytest

from tainttrap.core import paths
from tainttrap.core.policy import parse_policy
from tainttrap.core.rules.base import CallContext
from tainttrap.core.rules.self_protect import SelfProtect
from tainttrap.core.types import RiskClass

POLICY = parse_policy({"mode": "soft"})


def verdict(tool, args, cwd="/repo"):
    ctx = CallContext(tool, None, args, RiskClass.WRITE_INTERNAL, [], {}, None, {"cwd": cwd})
    r = SelfProtect().evaluate(ctx, POLICY)
    return r.rule_id if r else None


def test_write_tools_on_protected_paths():
    cfg = paths.config_dir()
    assert verdict("Write", {"file_path": str(cfg / "policy.yaml")}) == "self_protect.config_path"
    assert verdict("Edit", {"file_path": "~/.claude/settings.json"}) == "self_protect.config_path"
    assert (
        verdict("Edit", {"file_path": ".claude/settings.local.json"}) == "self_protect.config_path"
    )
    assert (
        verdict("write_file", {"path": str(paths.runtime_dir() / "hook.json")})
        == "self_protect.config_path"
    )
    assert (
        verdict("Write", {"file_path": "/etc/claude-code/managed-settings.json"})
        == "self_protect.config_path"
    )
    assert verdict("Write", {"file_path": "/repo/src/app.py"}) is None


def test_reading_is_allowed():
    cfg = paths.config_dir()
    assert verdict("Read", {"file_path": str(cfg / "policy.yaml")}) is None
    assert verdict("Bash", {"command": f"cat {cfg}/policy.yaml"}) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "echo 'mode: observe' > {cfg}/policy.yaml",
        "rm -rf {home}",
        "mv {cfg}/policy.yaml /tmp/x",
        "sed -i s/soft/observe/ {cfg}/policy.yaml",
        "pkill -f tainttrap",
        "launchctl unload ~/Library/LaunchAgents/tainttrap.plist",
    ],
)
def test_shell_tampering(cmd):
    cmd = cmd.format(cfg=paths.config_dir(), home=paths.home_dir())
    assert verdict("Bash", {"command": cmd}) is not None


@pytest.mark.parametrize(
    "cmd",
    [
        "tainttrap approve apv_01",
        "tainttrap deny apv_01",
        "tainttrap approvals",
        "tainttrap daemon stop",
        "tainttrap daemon reload",
        "tainttrap policy mode observe",
        "tainttrap policy apply x.yaml",
        "tainttrap registry add evil --risk read_only --description x",
        "tainttrap flag 01J --correct allow",
        "tainttrap install claude-code",
        "tainttrap uninstall claude-code",
        "tainttrap model shadow enable v2",
        "tainttrap-hook pre-tool",
        "python -m tainttrap.daemon",
        "/opt/bin/tainttrap policy mode observe",
        "env FOO=1 tainttrap policy mode observe",
        "ls && tainttrap approve apv_1",
        "uv run tainttrap daemon stop",
    ],
)
def test_state_changing_tainttrap_commands_blocked(cmd):
    assert (
        verdict("Bash", {"command": cmd}) == "self_protect.command"
        or verdict("Bash", {"command": cmd}) is not None
    )


@pytest.mark.parametrize(
    "cmd",
    [
        "tainttrap report --since 7d",
        "tainttrap log",
        "tainttrap log show 01J",
        "tainttrap status",
        "tainttrap daemon status",
        "tainttrap policy show",
        "tainttrap policy validate p.yaml",
        "tainttrap registry list",
        "tainttrap model info",
        "tainttrap --help",
        "npm run build",
    ],
)
def test_read_only_commands_allowed(cmd):
    assert verdict("Bash", {"command": cmd}) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "script -q /dev/null tainttrap approve apv_1",
        "script -qc 'tainttrap approve apv_1' /dev/null",
        "python3 -c \"import pty; pty.spawn(['tainttrap', 'approve', 'apv_1'])\"",
        "bash -c 'tainttrap policy mode observe'",
        "expect -c 'spawn tainttrap deny apv_1'",
        "python3 -c 'from tainttrap.cli.admin import admin_request; admin_request(\"approve\")'",
        "nc -U ~/Library/Caches/tainttrap/admin.sock",
        "socat - UNIX-CONNECT:/tmp/tt-501/check.sock",
    ],
)
def test_wrapped_and_indirect_invocations_blocked(cmd):
    assert verdict("Bash", {"command": cmd}) is not None


@pytest.mark.parametrize(
    "cmd",
    [
        "script -q /dev/null tainttrap report --since 1d",
        "bash -c 'tainttrap daemon status'",
        "cd ~/code/tainttrap && ls",
        "grep -r tainttrap docs/",
    ],
)
def test_wrapped_read_only_allowed(cmd):
    assert verdict("Bash", {"command": cmd}) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json",
        "cd .claude && echo '{}' > settings.local.json",
        "cd .claude; cp /tmp/x settings.json",
        "python3 -c \"import json;open('.claude/settings.local.json','w').write('{}')\"",
        "jq '.disableAllHooks=true' .claude/settings.json > /tmp/s && mv /tmp/s .claude/settings.json",
        "printf '{\"disableAllHooks\": true}' > /tmp/x.json",
        "sed -i '' 's/claude_code/daemon/' ~/Library/Caches/tainttrap/hook.json",
        "git checkout -- .claude/settings.json",
    ],
)
def test_settings_tampering_blocked(cmd):
    assert verdict("Bash", {"command": cmd}) is not None, cmd


@pytest.mark.parametrize(
    "cmd",
    [
        "cat .claude/settings.json",
        "grep disableAllHooks .claude/settings.local.json",
        "jq .hooks .claude/settings.json",
        "git diff .claude/settings.json",
        "cd .claude && ls",
        "cp config/settings.json build/",  # a project's own settings.json, not Claude Code's
        "git commit -m 'block disableAllHooks writes'",
        "grep -rn disableAllHooks specs/",
    ],
)
def test_reading_settings_allowed(cmd):
    assert verdict("Bash", {"command": cmd}) is None, cmd


def test_write_tool_content_with_hook_switch_blocked():
    assert (
        verdict("Write", {"file_path": "/tmp/notes.json", "content": '{"disableAllHooks": true}'})
        is not None
    )
    assert (
        verdict(
            "Edit",
            {
                "file_path": "/repo/a.json",
                "old_string": "x",
                "new_string": '"allowManagedHooksOnly": true',
            },
        )
        is not None
    )
    assert verdict("Write", {"file_path": "/repo/a.json", "content": '{"ok": true}'}) is None


def test_relative_write_inside_claude_dir_blocked():
    assert verdict("Write", {"file_path": "settings.local.json"}, cwd="/repo/.claude") is not None
