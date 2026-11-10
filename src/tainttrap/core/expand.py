"""One-level expansion of task-runner commands (`make <target>`, `npm run <script>`,
`just <recipe>`), so rules and the model see what the command will really run.

Known limit (research R-06): the recipe is read at check time. An agent that edits the
Makefile between the check and the run defeats this; self-protection does not cover
project files.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 256 * 1024
SHELL_KEYS = ("command", "cmd", "script")
_SEGMENTS = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
_RECIPE_PREFIX = re.compile(r"^[@+\-]+")


def _read(path: Path) -> str | None:
    try:
        if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
            return path.read_text(errors="replace")
    except OSError:
        return None
    return None


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def make_recipe(makefile_text: str, target: str | None) -> list[str]:
    lines = makefile_text.splitlines()
    rule = re.compile(r"^([^\s:#=][^:=]*?)\s*::?(?!=)(.*)$")
    for i, line in enumerate(lines):
        m = rule.match(line)
        if not m or line.startswith("\t"):
            continue
        names = m.group(1).split()
        if names and names[0].startswith("."):
            continue
        if target is None or target in names:
            recipe = []
            inline = m.group(2).split(";", 1)
            if len(inline) == 2 and inline[1].strip():
                recipe.append(inline[1].strip())
            for body in lines[i + 1 :]:
                if not body.startswith("\t"):
                    if body.strip() == "":
                        continue
                    break
                recipe.append(_RECIPE_PREFIX.sub("", body.strip()))
            return recipe
    return []


def npm_scripts(package_json: str, name: str) -> list[str]:
    try:
        scripts = json.loads(package_json).get("scripts") or {}
    except (json.JSONDecodeError, AttributeError):
        return []
    return [
        scripts[n] for n in (f"pre{name}", name, f"post{name}") if isinstance(scripts.get(n), str)
    ]


def just_recipe(justfile: str, name: str) -> list[str]:
    lines = justfile.splitlines()
    head = re.compile(rf"^@?{re.escape(name)}(\s[^:]*)?:(?!=)")
    for i, line in enumerate(lines):
        if head.match(line):
            out = []
            for body in lines[i + 1 :]:
                if body[:1] in (" ", "\t") and body.strip():
                    out.append(_RECIPE_PREFIX.sub("", body.strip()))
                elif body.strip():
                    break
            return out
    return []


def expand_command(command: str, cwd: str | None) -> list[str]:
    """Recipes the command would run, one level deep. Empty if nothing to expand."""
    here = Path(cwd) if cwd else None
    out: list[str] = []
    for segment in _SEGMENTS.split(command):
        toks = _tokens(segment)
        if not toks:
            continue
        prog = os.path.basename(toks[0])
        if prog == "cd" and here is not None:
            target = toks[1] if len(toks) > 1 else "~"
            here = (
                Path(os.path.expanduser(target))
                if os.path.isabs(os.path.expanduser(target))
                else here / target
            )
            continue
        if here is None:
            continue
        if prog in ("make", "gmake"):
            out += _expand_make(toks[1:], here)
        elif prog in ("npm", "pnpm", "yarn"):
            args = toks[1:]
            if args[:1] in (["run"], ["run-script"]):
                args = args[1:]
            elif prog == "npm" and args[:1] not in (["test"], ["start"]):
                continue
            if args:
                text = _read(here / "package.json")
                if text:
                    out += npm_scripts(text, args[0])
        elif prog == "just" and len(toks) > 1:
            text = _read(here / "justfile") or _read(here / "Justfile")
            if text:
                out += just_recipe(text, toks[1])
    return out


def _expand_make(args: list[str], here: Path) -> list[str]:
    directory, makefile, targets = here, None, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "--directory") and i + 1 < len(args):
            directory = directory / args[i + 1]
            i += 2
            continue
        if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
            makefile = args[i + 1]
            i += 2
            continue
        if not a.startswith("-") and "=" not in a:
            targets.append(a)
        i += 1
    names = [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]
    text = next((t for t in (_read(directory / n) for n in names) if t), None)
    if text is None:
        return []
    out: list[str] = []
    goals: list[str | None] = list(targets) or [None]  # None = the default goal
    for t in goals:
        out += make_recipe(text, t)
    return out


def expand_arguments(arguments: dict[str, Any], cwd: str | None) -> dict[str, Any]:
    """Return arguments plus `expanded_command` when a task runner is invoked."""
    for key in SHELL_KEYS:
        cmd = arguments.get(key)
        if isinstance(cmd, str):
            recipes = expand_command(cmd, cwd)
            if recipes:
                return {**arguments, "expanded_command": " ; ".join(recipes)}
            return arguments
    return arguments
