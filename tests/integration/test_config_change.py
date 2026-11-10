"""ConfigChange hook: any settings edit is reported, and the daemon re-checks the hooks."""

import json
import os
import subprocess
import sys

from tainttrap.cli import doctor as doc
from tainttrap.cli.install import add_ours
from tainttrap.core import paths
from tainttrap.daemon.embedded import EmbeddedDaemon
from tainttrap.logstore.writer import read_entries


class Notes:
    name = "stub"

    def __init__(self):
        self.messages = []

    def deliver(self, code, purpose):
        return True

    def notify(self, message):
        self.messages.append(message)


def fire(event):
    env = {**os.environ, "TAINTTRAP_NO_AUTOSTART": "1"}
    subprocess.run(
        [sys.executable, "-m", "tainttrap.hookclient", "config-change"],
        input=json.dumps(event),
        text=True,
        env=env,
        capture_output=True,
        timeout=20,
        check=True,
    )


def test_disabling_hooks_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(doc.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(doc, "MANAGED", ())
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(add_ours({}, "/v/tainttrap-hook", 60))
    )
    notes = Notes()
    with EmbeddedDaemon(confirm=notes):
        fire(
            {
                "session_id": "s",
                "cwd": str(project),
                "source": "project_local",
                "file_path": str(project / ".claude/settings.local.json"),
            }
        )
        healthy = [e["kind"] for e in read_entries(paths.logs_dir())]
        (project / ".claude" / "settings.local.json").write_text(
            json.dumps({"disableAllHooks": True})
        )
        fire(
            {
                "session_id": "s",
                "cwd": str(project),
                "source": "project_local",
                "file_path": str(project / ".claude/settings.local.json"),
            }
        )
    kinds = [e["kind"] for e in read_entries(paths.logs_dir())]
    assert "config_changed" in healthy and "hooks_missing" not in healthy
    assert kinds.count("config_changed") == 2 and "hooks_missing" in kinds
    assert notes.messages and "disableAllHooks" in notes.messages[0]


def test_doctor_wants_a_managed_config_change_hook(tmp_path, monkeypatch):
    monkeypatch.setattr(doc.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(doc, "MANAGED", ())
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(add_ours({}, "/v/tainttrap-hook", 60))
    )
    warnings = [m for lv, m in doc.diagnose(tmp_path, check_daemon=False) if lv == "warn"]
    assert any("ConfigChange hook is not managed" in m for m in warnings)
