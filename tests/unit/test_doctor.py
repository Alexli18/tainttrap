import json

from tainttrap.cli import doctor as doc
from tainttrap.cli.install import add_ours
from tainttrap.daemon.embedded import EmbeddedDaemon


def levels(results):
    return {(lv, m.split(":")[0]) for lv, m in results}


def test_healthy_install(tmp_path, monkeypatch):
    monkeypatch.setattr(doc.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(doc, "MANAGED", ())
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(add_ours({}, "/v/tainttrap-hook", 60))
    )
    with EmbeddedDaemon():
        results = doc.diagnose(tmp_path / "proj")
    assert not [m for lv, m in results if lv == "error"], results


def test_detects_quiet_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(doc.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(doc, "MANAGED", ())
    (tmp_path / ".claude").mkdir()
    settings = add_ours({}, "/v/tainttrap-hook", 60)
    hook = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    del hook["onFailure"]
    hook["timeout"] = 30
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(settings))
    proj = tmp_path / "proj" / ".claude"
    proj.mkdir(parents=True)
    (proj / "settings.local.json").write_text(json.dumps({"disableAllHooks": True}))
    msgs = " | ".join(m for lv, m in doc.diagnose(tmp_path / "proj") if lv == "error")
    assert "daemon not running" in msgs
    assert "disableAllHooks" in msgs
    assert "onFailure" in msgs
    assert "hook timeout 30 s" in msgs


def test_no_hook_at_all(tmp_path, monkeypatch):
    monkeypatch.setattr(doc.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(doc, "MANAGED", ())
    msgs = [m for lv, m in doc.diagnose(tmp_path) if lv == "error"]
    assert any("no TaintTrap PreToolUse hook" in m for m in msgs)
