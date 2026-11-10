import json, os, subprocess, sys, tempfile, time
from pathlib import Path
base = Path(tempfile.mkdtemp(prefix="tp", dir="/tmp"))
for name, sub in (("TAINTTRAP_HOME","home"),("TAINTTRAP_CONFIG_DIR","cfg"),("TAINTTRAP_RUNTIME_DIR","run")):
    (base/sub).mkdir(mode=0o700); os.environ[name]=str(base/sub)
os.environ["TAINTTRAP_NO_AUTOSTART"]="1"
from tainttrap.daemon.embedded import EmbeddedDaemon
HOOK=[sys.executable,"-m","tainttrap.hookclient"]
def hook(cmd, event, raw=None):
    r = subprocess.run([*HOOK, cmd], input=raw if raw is not None else json.dumps(event), capture_output=True, text=True, timeout=60)
    return r
def pre(sid, tool, inp, tid="toolu_9"):
    r = hook("pre-tool", {"session_id":sid,"cwd":"/repo","tool_name":tool,"tool_use_id":tid,"tool_input":inp})
    return (json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout else "allow(none)")
def post(sid, tool, resp, tid="toolu_0", raw=None):
    return hook("post-tool", {"session_id":sid,"cwd":"/repo","tool_name":tool,"tool_use_id":tid,"tool_response":resp}, raw=raw)
def prompt(sid, text):
    hook("user-prompt", {"session_id":sid,"cwd":"/repo","prompt":text})
def errors():
    p = base/"home"/"hook-errors.log"
    return p.read_text() if p.exists() else ""
