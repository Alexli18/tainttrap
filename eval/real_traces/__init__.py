"""Real coding-agent traces (OpenHands, SWE-Hero) for measuring false positives (2026-10-11).

The data stays in a cache outside git (`~/.cache/tainttrap-data/swe/`, `TAINTTRAP_DATA_CACHE`
to override). `sample.json` in this directory pins the source (repository, revision, shard,
sha256) and lists which trajectories and which bash calls form the frozen evaluation sample.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "sample.json"  # frozen, held out
DEV_SAMPLE = HERE / "dev_sample.json"  # for iterating on fixes; disjoint from SAMPLE
DEV_SEED = 7
DEV_TRAJECTORIES = 200
SOURCE = {
    "repo": "nvidia/SWE-Hero-openhands-trajectories",
    "revision": "150bc119e52c647216fce285fd801f16b6fd745b",
    "file": "data/train-00013-of-00014.parquet",
    "sha256": "936b195ed11b2b9be2e60cf9cb274dfc2f31d07745cbd6144658da988ce295a9",
    "license": "CC-BY-4.0",
}
SEED = 20261011
TRAJECTORIES = 400
CALLS_PER_TRAJECTORY = 5


def cache_dir() -> Path:
    return Path(os.environ.get("TAINTTRAP_DATA_CACHE", Path.home() / ".cache" / "tainttrap-data"))


def shard_path() -> Path:
    return cache_dir() / "swe" / "swe-hero" / SOURCE["file"]


def fetch() -> Path:
    """Download the pinned shard into the cache (needs the `data` extra)."""
    p = shard_path()
    if not p.exists():
        from huggingface_hub import hf_hub_download

        hf_hub_download(
            SOURCE["repo"],
            SOURCE["file"],
            repo_type="dataset",
            revision=SOURCE["revision"],
            local_dir=p.parents[1],
        )
    verify(p)
    return p


def verify(p: Path) -> None:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != SOURCE["sha256"]:
        raise RuntimeError(f"{p}: sha256 does not match the pinned shard")


def available() -> bool:
    return shard_path().exists()


@dataclass
class Call:
    """One assistant tool call, mapped to TaintTrap's tool names (None: not a tool action)."""

    index: int
    source_tool: str
    source_args: dict[str, Any]
    tool: str | None
    arguments: dict[str, Any]
    output: str | None
    bash: bool = False


@dataclass
class Trajectory:
    trajectory_id: str
    instance_id: str
    repo: str
    license: str
    task: str
    calls: list[Call] = field(default_factory=list)


def map_call(name: str, args: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """OpenHands tool call -> (Claude Code tool name, arguments). See MAPPING."""
    if name == "execute_bash":
        if str(args.get("is_input", "")).strip().lower() == "true":
            return None, {}  # keystrokes into a running process, not a new command
        return "Bash", {"command": str(args.get("command", ""))}
    if name == "str_replace_editor":
        cmd, path = args.get("command"), str(args.get("path", ""))
        if cmd == "view":
            return "Read", {"file_path": path}
        if cmd == "create":
            return "Write", {"file_path": path, "content": str(args.get("file_text") or "")}
        if cmd == "str_replace":
            return "Edit", {
                "file_path": path,
                "old_string": str(args.get("old_str") or ""),
                "new_string": str(args.get("new_str") or ""),
            }
        if cmd == "insert":
            return "Edit", {
                "file_path": path,
                "old_string": "",
                "new_string": str(args.get("new_str") or ""),
            }
        if cmd == "undo_edit":
            return "Edit", {"file_path": path, "old_string": "", "new_string": ""}
        return None, {}
    return None, {}  # think, finish: the model's own notes and final answer, no action


MAPPING = [
    ("execute_bash {command}", "Bash {command}"),
    ("execute_bash {is_input: true}", "not checked: input to a running process"),
    ("str_replace_editor view {path}", "Read {file_path}"),
    ("str_replace_editor create {path, file_text}", "Write {file_path, content}"),
    (
        "str_replace_editor str_replace {path, old_str, new_str}",
        "Edit {file_path, old_string, new_string}",
    ),
    ("str_replace_editor insert {path, new_str}", "Edit {file_path, new_string}"),
    ("str_replace_editor undo_edit {path}", "Edit {file_path}"),
    ("think {thought}", "not checked: the model's own note"),
    ("finish {message}", "not checked: the final answer"),
]


def _task(messages: list[dict[str, Any]]) -> str:
    return next((str(m.get("content") or "") for m in messages if m.get("role") == "user"), "")


def parse(row: dict[str, Any]) -> Trajectory:
    msgs = row["trajectory"]
    t = Trajectory(
        row["trajectory_id"], row["instance_id"], row["repo"], row["license"], _task(msgs)
    )
    for i, m in enumerate(msgs):
        if m.get("role") != "assistant" or not m.get("tool_calls"):
            continue
        fn = m["tool_calls"][0]["function"]
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}
        nxt = msgs[i + 1] if i + 1 < len(msgs) else None
        out = str(nxt.get("content") or "") if nxt and nxt.get("role") == "tool" else None
        tool, mapped = map_call(fn["name"], args if isinstance(args, dict) else {})
        t.calls.append(Call(len(t.calls), fn["name"], args, tool, mapped, out, tool == "Bash"))
    return t


def read_rows(ids: set[str] | None = None) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    p = shard_path()
    verify(p)
    cols = ["trajectory_id", "instance_id", "repo", "license", "trajectory"]
    rows = pq.read_table(p, columns=cols).to_pylist()
    return [r for r in rows if ids is None or r["trajectory_id"] in ids]


def make_sample(
    seed: int = SEED, size: int = TRAJECTORIES, exclude: set[str] | None = None
) -> dict[str, Any]:
    """Pick `size` trajectories and CALLS_PER_TRAJECTORY bash calls in each, seeded."""
    rng = random.Random(seed)
    rows = sorted(read_rows(), key=lambda r: r["trajectory_id"])
    rows = [r for r in rows if r["trajectory_id"] not in (exclude or set())]
    picks: dict[str, list[int]] = {}
    for r in rng.sample(rows, len(rows)):
        t = parse(r)
        bash = [c.index for c in t.calls if c.bash and c.arguments["command"].strip()]
        if len(bash) < CALLS_PER_TRAJECTORY:
            continue
        picks[t.trajectory_id] = sorted(rng.sample(bash, CALLS_PER_TRAJECTORY))
        if len(picks) == size:
            break
    return {"source": SOURCE, "seed": seed, "picks": dict(sorted(picks.items()))}


def make_dev_sample() -> dict[str, Any]:
    frozen = set(json.loads(SAMPLE.read_text())["picks"])
    return make_sample(DEV_SEED, DEV_TRAJECTORIES, exclude=frozen)


def load_sample(path: Path = SAMPLE) -> tuple[dict[str, Any], list[Trajectory]]:
    sample = json.loads(path.read_text())
    rows = read_rows(set(sample["picks"]))
    trajs = sorted((parse(r) for r in rows), key=lambda t: t.trajectory_id)
    return sample, trajs
