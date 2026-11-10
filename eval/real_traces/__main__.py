"""False positives of the frozen rules on real coding-agent work (2026-10-11).

    uv run --extra data python -m eval.real_traces fetch      # pinned shard into the cache
    uv run --extra data python -m eval.real_traces sample     # (re)write sample.json; deliberate
    uv run --extra data python -m eval.real_traces run [--mode soft|strict]

Each sampled trajectory is replayed in its own session against one embedded daemon with clean
state: the issue text is the user's task, every mapped call is checked and its real output is
observed (so provenance tracking sees what the agent read), and only the sampled bash calls are
scored. All of them are benign (normal work on an issue), so any ask or block is a false
positive. Other mapped calls (Read, Write, Edit) are reported apart. OpenHands tool names are
mapped to Claude Code's (`MAPPING` in __init__.py); without that every call would be an
unknown tool.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.local_agent.__main__ import fresh_state, wilson
from eval.real_traces import (
    DEV_SAMPLE,
    MAPPING,
    SAMPLE,
    fetch,
    load_sample,
    make_dev_sample,
    make_sample,
)
from tainttrap.client import TaintTrapClient
from tainttrap.core.masking import mask_text

REPORTS = Path(__file__).resolve().parents[1] / "reports"
EXAMPLES_PER_REASON = 8


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n if n else None, "ci95": wilson(k, n) if n else None}


def _short(s: str, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", mask_text(s)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def run(mode: str, path: Path = SAMPLE) -> dict[str, Any]:
    sample, trajs = load_sample(path)
    picks = {k: set(v) for k, v in sample["picks"].items()}
    rows: list[dict[str, Any]] = []
    others: Counter[tuple[str, str]] = Counter()
    ms: list[float] = []
    ws = Path(tempfile.mkdtemp(prefix="tt-real-"))
    with fresh_state(mode):
        for t in trajs:
            # One working directory per trajectory: the daemon shares provenance across sessions
            # in the same directory, and these trajectories are unrelated projects.
            cwd = ws / t.trajectory_id
            cwd.mkdir()
            gate = TaintTrapClient(session_id=f"rt-{uuid.uuid4().hex[:8]}", cwd=str(cwd))
            try:
                gate.task(t.task, source="proxy_config")
                for c in t.calls:
                    if c.tool is None:
                        continue
                    cid = f"c{c.index}"
                    t0 = time.perf_counter()
                    d = gate.check(c.tool, c.arguments, cid)
                    elapsed = (time.perf_counter() - t0) * 1000
                    if c.index in picks[t.trajectory_id]:
                        ms.append(elapsed)
                        rows.append(
                            {
                                "trajectory_id": t.trajectory_id,
                                "repo": t.repo,
                                "call_index": c.index,
                                "command": _short(c.arguments["command"], 300),
                                "task": _short(t.task.split("<issue_description>")[-1], 200),
                                "outcome": d.outcome,
                                "decided_by": d.decided_by,
                                "reason": d.reason,
                                "reason_codes": list(d.reason_codes),
                                "error": d.error,
                            }
                        )
                    elif not c.bash:
                        others[(c.tool, d.outcome)] += 1
                    if c.output is not None:
                        gate.observe(cid, c.tool, c.output)
            finally:
                gate.end()
                gate.close()

    n = len(rows)
    by_reason: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r["outcome"] != "allow":
            key = f"{r['outcome']}: " + (", ".join(r["reason_codes"]) or r["reason"])
            by_reason[key].append(r)
    reasons = {
        k: {
            "count": len(v),
            "examples": [
                {"command": r["command"], "task": r["task"], "reason": r["reason"]}
                for r in v[:EXAMPLES_PER_REASON]
            ],
        }
        for k, v in sorted(by_reason.items(), key=lambda kv: -len(kv[1]))
    }
    other_tools: dict[str, dict[str, int]] = defaultdict(dict)
    for (tool, outcome), k in sorted(others.items()):
        other_tools[tool][outcome] = k
    return {
        "created": datetime.now(UTC).isoformat(),
        "mode": mode,
        "source": sample["source"],
        "mapping": MAPPING,
        "trajectories": len(trajs),
        "bash_calls_scored": n,
        "allowed_without_question": rate(sum(r["outcome"] == "allow" for r in rows), n),
        "asked": rate(sum(r["outcome"] == "ask" for r in rows), n),
        "blocked": rate(sum(r["outcome"] == "block" for r in rows), n),
        "trajectories_with_any_question_or_block": rate(
            len({r["trajectory_id"] for r in rows if r["outcome"] != "allow"}), len(trajs)
        ),
        "decided_by": dict(Counter(f"{r['outcome']}:{r['decided_by']}" for r in rows)),
        "errors": sum(1 for r in rows if r["error"]),
        "check_ms": {"p50": statistics.median(ms), "p95": sorted(ms)[int(len(ms) * 0.95)]},
        "reasons": reasons,
        "other_tools": other_tools,
        "rows": rows,
    }


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m eval.real_traces")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    sub.add_parser("sample")
    sub.add_parser("dev-sample")
    r = sub.add_parser("run")
    r.add_argument("--mode", choices=["soft", "strict"], default="soft")
    r.add_argument(
        "--dev", action="store_true", help="the working sample for iterating, not the frozen one"
    )
    r.add_argument("--out", type=Path)
    args = ap.parse_args()
    if args.cmd == "fetch":
        print(fetch())
        return
    if args.cmd == "sample":
        s = make_sample()
        SAMPLE.write_text(json.dumps(s, indent=1) + "\n")
        print(f"sampled {len(s['picks'])} trajectories, {sum(map(len, s['picks'].values()))} calls")
        return
    if args.cmd == "dev-sample":
        s = make_dev_sample()
        DEV_SAMPLE.write_text(json.dumps(s, indent=1) + "\n")
        print(f"dev sample: {len(s['picks'])} trajectories, disjoint from {SAMPLE.name}")
        return
    rep = run(args.mode, DEV_SAMPLE if args.dev else SAMPLE)
    rep["sample"] = "dev" if args.dev else "frozen"

    def cell(m: dict[str, Any]) -> str:
        lo, hi = m["ci95"]
        return f"{m['k']}/{m['n']} = {m['rate']:.1%} (95% CI {lo:.1%}-{hi:.1%})"

    print(f"bash calls scored: {rep['bash_calls_scored']} from {rep['trajectories']} trajectories")
    print(f"allowed without a question: {cell(rep['allowed_without_question'])}")
    print(f"asked:                      {cell(rep['asked'])}")
    print(f"blocked:                    {cell(rep['blocked'])}")
    print(
        "trajectories with any ask or block: "
        + cell(rep["trajectories_with_any_question_or_block"])
    )
    print(f"decided by: {rep['decided_by']}  errors: {rep['errors']}")
    for k, v in rep["reasons"].items():
        print(f"\n[{v['count']}] {k}")
        for e in v["examples"][:3]:
            print(f"    $ {e['command'][:140]}")
    print(f"\nother tools: {rep['other_tools']}")
    print(f"check latency p50 {rep['check_ms']['p50']:.1f} ms, p95 {rep['check_ms']['p95']:.1f} ms")
    out = args.out or REPORTS / f"real-traces-swe-hero-{rep['sample']}-{rep['mode']}.json"
    out.write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    print(f"report: {out}")


if __name__ == "__main__":
    main()
