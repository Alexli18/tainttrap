import json

from click.testing import CliRunner

from tainttrap.cli import install as inst
from tainttrap.cli.main import cli


def test_install_merges_and_uninstall_restores(tmp_path, monkeypatch):
    monkeypatch.setattr(inst.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(inst, "hook_binary", lambda: "/venv/bin/tainttrap-hook")
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    mine = {
        "model": "x",
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-lint"}]}
            ]
        },
    }
    settings.write_text(json.dumps(mine))

    r = CliRunner().invoke(cli, ["install", "claude-code", "--yes"])
    assert r.exit_code == 0, r.output
    data = json.loads(settings.read_text())
    pre = data["hooks"]["PreToolUse"]
    assert pre[0]["hooks"][0]["command"] == "my-lint"
    assert pre[1] == {
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": "/venv/bin/tainttrap-hook pre-tool",
                "timeout": 90,
                "onFailure": "block",
            }
        ],
    }
    assert set(data["hooks"]) == {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",  # failed calls' output is observed too (T142)
        "SessionStart",  # sessions the daemon saw start (T155)
        "UserPromptSubmit",
        "SessionEnd",
        "ConfigChange",
    }
    assert (settings.parent / "settings.json.tainttrap.bak").exists()

    r2 = CliRunner().invoke(cli, ["install", "claude-code", "--yes"])
    assert "already up to date" in r2.output  # idempotent

    r3 = CliRunner().invoke(cli, ["uninstall", "claude-code", "--yes"])
    assert r3.exit_code == 0
    assert json.loads(settings.read_text()) == mine


def test_dry_run_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(inst.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(inst, "hook_binary", lambda: "/venv/bin/tainttrap-hook")
    r = CliRunner().invoke(cli, ["install", "claude-code", "--dry-run"])
    assert r.exit_code == 0 and "tainttrap-hook pre-tool" in r.output
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_status_without_daemon_exits_2():
    r = CliRunner().invoke(cli, ["status"])
    assert r.exit_code == 2


def test_fail_closed_sets_on_failure_block(tmp_path, monkeypatch):
    from tainttrap.core import paths

    monkeypatch.setattr(inst.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(inst, "hook_binary", lambda: "/venv/bin/tainttrap-hook")
    paths.policy_file().write_text("version: 1\nfailure_mode: fail_closed\n")
    r = CliRunner().invoke(cli, ["install", "claude-code", "--yes"])
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    pre = data["hooks"]["PreToolUse"][0]["hooks"][0]
    assert pre["onFailure"] == "block"
    assert "onFailure" not in data["hooks"]["PostToolUse"][0]["hooks"][0]


def test_managed_scope_with_disable_bypass(tmp_path, monkeypatch):
    managed = tmp_path / "managed-settings.json"
    monkeypatch.setattr(inst, "MANAGED_SETTINGS", {"darwin": managed, "linux": managed})
    monkeypatch.setattr(inst, "hook_binary", lambda: "/opt/tainttrap/bin/tainttrap-hook")
    r = CliRunner().invoke(
        cli, ["install", "claude-code", "--scope", "managed", "--disable-bypass", "--yes"]
    )
    assert r.exit_code == 0, r.output
    data = json.loads(managed.read_text())
    assert data["permissions"]["disableBypassPermissionsMode"] == "disable"
    assert "ConfigChange" in data["hooks"] and "best-effort" not in r.output


def test_install_keeps_non_ascii_text_unescaped(tmp_path, monkeypatch):
    import json as _json

    from tainttrap.cli import install as inst

    path = tmp_path / "settings.json"
    path.write_text(_json.dumps({"statusLine": {"command": "printf '➜ ✗'"}}, ensure_ascii=False))
    monkeypatch.setattr(inst, "settings_path", lambda scope: path)
    from click.testing import CliRunner

    from tainttrap.cli.main import cli

    r = CliRunner().invoke(cli, ["install", "claude-code", "--scope", "user", "--yes"])
    assert r.exit_code == 0, r.output
    text = path.read_text()
    assert "➜ ✗" in text and "\\u279c" not in text
