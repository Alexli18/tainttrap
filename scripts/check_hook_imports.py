"""Fail if importing the hook client pulls in anything outside the standard library."""

import subprocess
import sys

code = (
    "import sys; before=set(sys.modules); import tainttrap.hookclient; "
    "print('\\n'.join(sorted(set(sys.modules)-before)))"
)
out = subprocess.run(
    [sys.executable, "-c", code], capture_output=True, text=True, check=True
).stdout
stdlib = set(sys.stdlib_module_names)
bad = [m for m in out.split() if m.split(".")[0] not in stdlib and not m.startswith("tainttrap")]
loaded_ag = [
    m
    for m in out.split()
    if m.startswith("tainttrap") and m not in ("tainttrap", "tainttrap.hookclient")
]
if bad or loaded_ag:
    print("non-stdlib imports:", bad, "extra tainttrap modules:", loaded_ag)
    sys.exit(1)
print("hook client imports OK")
