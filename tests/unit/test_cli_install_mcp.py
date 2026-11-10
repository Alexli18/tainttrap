import json

import pytest
from click.testing import CliRunner

from tainttrap.cli import install as inst
from tainttrap.cli.main import cli

ORIG = {
    "github": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_TOKEN": "${GH}"},
    },
    "fs": {"type": "stdio", "command": "mcp-fs"},
    "remote": {"type": "http", "url": "https://mcp.example/mcp"},
}


@pytest.mark.parametrize(
    "client, rel, key",
    [
        ("claude-code", ".mcp.json", "mcpServers"),
        ("cursor", ".cursor/mcp.json", "mcpServers"),
        ("vscode", ".vscode/mcp.json", "servers"),
    ],
)
def test_wrap_and_restore(tmp_path, monkeypatch, client, rel, key):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inst, "tainttrap_binary", lambda: "/venv/bin/tainttrap")
    cfg = tmp_path / rel
    cfg.parent.mkdir(exist_ok=True)
    cfg.write_text(json.dumps({key: ORIG, "other": 1}))

    r = CliRunner().invoke(cli, ["install", "mcp", "--client", client, "--yes"])
    assert r.exit_code == 0, r.output
    data = json.loads(cfg.read_text())
    gh = data[key]["github"]
    assert gh["command"] == "/venv/bin/tainttrap"
    assert gh["args"] == [
        "run",
        "--server",
        "github",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github",
    ]
    assert gh["env"] == {"GITHUB_TOKEN": "${GH}"}
    assert data[key]["fs"]["type"] == "stdio"
    assert data[key]["remote"] == ORIG["remote"]  # HTTP servers are skipped
    assert "skip remote" in r.output

    again = CliRunner().invoke(cli, ["install", "mcp", "--client", client, "--yes"])
    assert "already up to date" in again.output

    CliRunner().invoke(cli, ["uninstall", "mcp", "--client", client, "--yes"])
    assert json.loads(cfg.read_text()) == {key: ORIG, "other": 1}


def test_only_selected_servers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inst, "tainttrap_binary", lambda: "/venv/bin/tainttrap")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": ORIG}))
    CliRunner().invoke(
        cli, ["install", "mcp", "--client", "claude-code", "--server", "fs", "--yes"]
    )
    data = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]
    assert data["github"] == ORIG["github"] and data["fs"]["command"] == "/venv/bin/tainttrap"
