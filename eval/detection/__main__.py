"""Detection benchmark: replay the call a compliant agent would make (no LLM involved).

    python -m eval.detection                 # all families, soft mode
    python -m eval.detection --mode strict --family task_runner

Measures TaintTrap itself, apart from whether a given model obeys an injection. Each case runs
in its own session against one embedded daemon with clean state; no approvals are given, so no
recipient is ever remembered and cases cannot influence each other. The earlier steps of the
session are checked and observed exactly as an adapter would; only the last call is scored.

Caught = the decision is not allow (block or ask, reported apart). For benign twins the number
that matters is the share allowed without a question.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detection.cases import FAMILIES, FIXTURES, Case, all_cases
from eval.local_agent.__main__ import fresh_state, wilson
from tainttrap.client import TaintTrapClient

REPORTS = Path(__file__).resolve().parents[1] / "reports"


def run_case(case: Case, root: Path) -> dict[str, Any]:
    ws = root / uuid.uuid4().hex[:8]
    shutil.copytree(FIXTURES, ws)
    for rel, text in case.workspace_files.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text)
    gate = TaintTrapClient(session_id=f"det-{uuid.uuid4().hex[:8]}", cwd=str(ws))
    try:
        gate.task(case.task, source="proxy_config")
        for i, step in enumerate(case.history):
            gate.check(step.tool, step.arguments, f"h{i}")
            gate.observe(f"h{i}", step.tool, step.response)
        t0 = time.perf_counter()
        d = gate.check(case.tool, case.arguments, "target")
        ms = (time.perf_counter() - t0) * 1000
    finally:
        gate.end()
        gate.close()
        shutil.rmtree(ws, ignore_errors=True)
    return {
        "id": case.id,
        "family": case.family,
        "variant": case.variant,
        "label": case.label,
        "hard": case.hard,
        "outcome": d.outcome,
        "decided_by": d.decided_by,
        "reason": d.reason,
        "reason_codes": list(d.reason_codes),
        "error": d.error,
        "ms": ms,
    }


def run(families: list[str] | None, mode: str) -> list[dict[str, Any]]:
    cases = all_cases(families)
    root = Path(tempfile.mkdtemp(prefix="ag-det-"))
    rows: list[dict[str, Any]] = []
    try:
        with fresh_state(mode):
            for c in cases:
                rows.append(run_case(c, root))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return rows


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n if n else None, "ci95": wilson(k, n) if n else None}


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    atk = [r for r in rows if r["label"] == "attack" and not r["hard"]]
    hard = [r for r in rows if r["label"] == "attack" and r["hard"]]
    ben = [r for r in rows if r["label"] == "benign"]
    return {
        "attack_caught": rate(sum(r["outcome"] != "allow" for r in atk), len(atk)),
        "attack_blocked": rate(sum(r["outcome"] == "block" for r in atk), len(atk)),
        "attack_asked": rate(sum(r["outcome"] == "ask" for r in atk), len(atk)),
        "hard_caught": rate(sum(r["outcome"] != "allow" for r in hard), len(hard)),
        "benign_allowed_no_question": rate(sum(r["outcome"] == "allow" for r in ben), len(ben)),
        "benign_asked": rate(sum(r["outcome"] == "ask" for r in ben), len(ben)),
        "benign_blocked": rate(sum(r["outcome"] == "block" for r in ben), len(ben)),
        "decided_by": dict(Counter(f"{r['label']}:{r['decided_by']}" for r in rows)),
        "misses": sorted(
            {f"{r['variant']}: {r['reason']}" for r in atk if r["outcome"] == "allow"}
        )[:20],
        "hard_misses": sorted({r["variant"] for r in hard if r["outcome"] == "allow"}),
        "false_alarms": sorted(
            {
                f"{r['variant']} -> {r['outcome']}: {r['reason']}"
                for r in ben
                if r["outcome"] != "allow"
            }
        )[:20],
        "errors": sum(1 for r in rows if r["error"]),
    }


def cell(m: dict[str, Any]) -> str:
    if not m["n"]:
        return "-".center(18)
    lo, hi = m["ci95"]
    return f"{m['rate']:4.0%} [{lo:.0%}-{hi:.0%}] n={m['n']}".ljust(18)


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m eval.detection")
    ap.add_argument("--family", action="append", choices=sorted(FAMILIES))
    ap.add_argument("--mode", choices=["soft", "strict"], default="soft")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    rows = run(args.family, args.mode)

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_family[r["family"]].append(r)
    summary = {f: summarize(rs) for f, rs in by_family.items()}
    summary["ALL"] = summarize(rows)

    cols = ("attacks caught", "blocked", "hard caught", "benign no question")
    head = f"{'family':18} " + " ".join(f"{c:26}" for c in cols)
    print(head)
    for f, s in summary.items():
        print(
            f"{f:18} {cell(s['attack_caught']):26} {cell(s['attack_blocked']):26} "
            f"{cell(s['hard_caught']):26} {cell(s['benign_allowed_no_question']):26}"
        )
    for f, s in summary.items():
        if f == "ALL":
            continue
        for m in s["misses"]:
            print(f"miss       {f}: {m}")
        for m in s["false_alarms"]:
            print(f"false alarm {f}: {m}")
    ms = [r["ms"] for r in rows]
    print(
        f"check latency: p50 {statistics.median(ms):.1f} ms, "
        f"p95 {sorted(ms)[int(len(ms) * 0.95)]:.1f} ms"
    )

    report = {
        "created": datetime.now(UTC).isoformat(),
        "mode": args.mode,
        "cases": len(rows),
        "summary": summary,
        "rows": rows,
    }
    out = args.out or REPORTS / f"detection-{args.mode}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"report: {out}")


if __name__ == "__main__":
    main()
