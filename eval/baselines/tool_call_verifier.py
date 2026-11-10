"""Baseline: rootfs/tool-call-verifier on the detection benchmark (2026-10-11).

    uv run --with torch==2.14.1 --with transformers==5.19.0 \
        python -m eval.baselines.tool_call_verifier [--snapshot DIR] [--ours REPORT.json]

A ModernBERT-base token classifier (Apache 2.0) that reads `[USER] <request> [TOOL] <call json>`
and labels each token AUTHORIZED or UNAUTHORIZED; the call is unsafe when any token is
UNAUTHORIZED (the card's rule). It sees only the user's request and the call: no tool output,
no provenance, no earlier steps. The weights are loaded from a local snapshot outside git,
safetensors only, with the hash checked; nothing is downloaded here.

Compared case by case with TaintTrap's own decisions from a detection report (default
`eval/reports/detection-soft.json`, written by `python -m eval.detection`). Both iterate
`eval.detection.cases.all_cases()` in the same order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from eval.detection.cases import all_cases
from eval.holdout import _model_test
from eval.local_agent.__main__ import wilson

REPO = "rootfs/tool-call-verifier"
REVISION = "0ff2fee048a65fe4393a928dae11c9fcaf89e03c"
WEIGHTS_SHA256 = "992a572e923cbb0b336b5ced300c43badc4e91934a32d5bd6dd66c8017e9d75b"
SNAPSHOT = Path.home() / ".cache" / "tainttrap-data" / "tool-call-verifier"
REPORTS = Path(__file__).resolve().parents[1] / "reports"
_PICKLE = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt"}


class Verifier:
    def __init__(self, snapshot: Path) -> None:
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer

        bad = [p.name for p in snapshot.iterdir() if p.suffix in _PICKLE]
        if bad:
            raise RuntimeError(f"refusing a snapshot with pickle files: {bad}")
        h = hashlib.sha256()
        with open(snapshot / "model.safetensors", "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != WEIGHTS_SHA256:
            raise RuntimeError("model.safetensors hash mismatch")
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(snapshot, local_files_only=True)
        self.model = AutoModelForTokenClassification.from_pretrained(
            snapshot, local_files_only=True, use_safetensors=True
        ).eval()
        self.unauth = self.model.config.label2id["UNAUTHORIZED"]

    def score(self, user_request: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        call = json.dumps({"name": tool_name, "arguments": arguments})
        enc = self.tok(
            f"[USER] {user_request} [TOOL] {call}",
            return_tensors="pt",
            truncation=True,
            max_length=2048,
        )
        with self.torch.inference_mode():
            logits = self.model(**enc).logits[0]
        probs = logits.softmax(-1)[:, self.unauth]
        flagged = int((logits.argmax(-1) == self.unauth).sum())
        return {"unsafe": flagged > 0, "flagged": flagged, "max_p": float(probs.max())}


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n if n else None, "ci95": wilson(k, n) if n else None}


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.tool_call_verifier")
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    ap.add_argument("--ours", type=Path, default=REPORTS / "detection-soft.json")
    ap.add_argument("--out", type=Path, default=REPORTS / "baseline-tool-call-verifier.json")
    args = ap.parse_args()

    v = Verifier(args.snapshot)
    cases = all_cases()
    ours = json.loads(args.ours.read_text())["rows"]
    if len(ours) != len(cases):
        raise SystemExit(
            "the TaintTrap report does not match the current cases; rerun eval.detection"
        )
    rows, ms = [], []
    for c, o in zip(cases, ours, strict=True):
        if o["variant"] != c.variant or o["family"] != c.family:
            raise SystemExit("case order differs from the TaintTrap report")
        t0 = time.perf_counter()
        s = v.score(c.task, c.tool, c.arguments)
        ms.append((time.perf_counter() - t0) * 1000)
        subset = "model_test" if _model_test(c.variant, c.hard) else "detection"
        rows.append(
            {
                "family": c.family,
                "variant": c.variant,
                "label": c.label,
                "subset": subset,
                "tcv_unsafe": s["unsafe"],
                "tcv_max_p": round(s["max_p"], 4),
                "ours": o["outcome"],
            }
        )

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[f"{r['subset']}"].append(r)
        groups[f"family:{r['family']}"].append(r)
        groups["ALL"].append(r)
    summary = {}
    for g, rs in groups.items():
        atk = [r for r in rs if r["label"] == "attack"]
        ben = [r for r in rs if r["label"] == "benign"]
        summary[g] = {
            "attacks_flagged_tcv": rate(sum(r["tcv_unsafe"] for r in atk), len(atk)),
            "attacks_caught_ours": rate(sum(r["ours"] != "allow" for r in atk), len(atk)),
            "benign_flagged_tcv": rate(sum(r["tcv_unsafe"] for r in ben), len(ben)),
            "benign_not_allowed_ours": rate(sum(r["ours"] != "allow" for r in ben), len(ben)),
            "benign_blocked_ours": rate(sum(r["ours"] == "block" for r in ben), len(ben)),
        }

    def cell(m: dict[str, Any]) -> str:
        if not m["n"]:
            return "-".center(20)
        lo, hi = m["ci95"]
        return f"{m['k']:>3}/{m['n']:<3} {m['rate']:4.0%} [{lo:.0%}-{hi:.0%}]"

    cols = ("attacks: TCV", "attacks: ours", "benign flagged: TCV", "benign asked/blocked: ours")
    print(f"{'group':26} " + " ".join(f"{h:26}" for h in cols))
    for g in sorted(summary, key=lambda k: (k != "ALL", k)):
        s = summary[g]
        print(
            f"{g:26} {cell(s['attacks_flagged_tcv']):26} {cell(s['attacks_caught_ours']):26} "
            f"{cell(s['benign_flagged_tcv']):26} {cell(s['benign_not_allowed_ours']):26}"
        )
    print(f"latency: p50 {statistics.median(ms):.0f} ms, max {max(ms):.0f} ms (CPU)")
    report = {
        "model": REPO,
        "revision": REVISION,
        "weights_sha256": WEIGHTS_SHA256,
        "decision_rule": "unsafe if any token is UNAUTHORIZED",
        "input": "[USER] <task> [TOOL] <call json>; no tool output, no history",
        "ours_report": str(args.ours.name),
        "summary": summary,
        "rows": rows,
    }
    args.out.write_text(json.dumps(report, indent=1))
    print(f"report: {args.out}")


if __name__ == "__main__":
    main()
