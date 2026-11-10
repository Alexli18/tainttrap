"""Frozen held-out sets: never in training, validation or threshold tuning (2026-10-11).

    python -m eval.holdout freeze             # rewrite eval/holdout.json (a deliberate act)
    python -m eval.holdout check FILE.jsonl   # training records vs held-out sets; exit 1 on overlap
    python -m eval.holdout attackers          # attacker hosts, addresses and payloads to avoid

Held out:
* every detection-benchmark case (`eval/detection`); the `hard`, paraphrased and lookalike-host
  cases are the `model_test` subset, which shows what the model adds over the rules;
* every local-agent scenario (`eval/local_agent/scenarios`);
* the external benchmarks named in the PRD (InjecAgent, AgentDojo, ...), which also go into
  `datasets.lock` with `allowed_split: eval_only` when they are pinned.

`holdout.json` stores each case's id, subset and content hash, so any edit to a held-out case
shows up as a failing test (`tests/unit/test_holdout.py`) until it is refrozen on purpose.

`check` rejects a training record (any split but `eval_only`) when:
1. its `meta.source` is a held-out source;
2. it repeats a held-out attack: same tool, a shared attack target (the registrable domain of a
   host, or an email address) and a shared payload (a sensitive path, a secret value, or an
   uploaded or attached file name). A held-out attack without a file or secret payload (a
   recipient swap) matches on tool and target alone. This catches a paraphrase that keeps the
   attacker's host or command;
3. at least half of the word 8-grams of its text fields come from one held-out case. Only text
   is compared (task, argument values, tool output, recent actions), never JSON keys or the
   registry's tool description, which every record with the same tool shares.

Every training record must say where it came from (`meta.source`, `source_version`, and
`generator` for synthetic data) so this check can run on the whole training set.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from tainttrap.core.domains import registrable_domain
from tainttrap.core.rules.base import command_hosts
from tainttrap.core.rules.secrets import scan_sensitive_paths, scan_value
from tainttrap.core.taint import refs

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "holdout.json"
SHINGLE = 8
CONTAINMENT = 0.5
EXTERNAL = (
    "injecagent",
    "agentdojo",
    "a3s_bench",
    "agent_injection_bench",
    "mcp_safetybench",
    "mcp_security_bench",
    "mcptox",
    "asb",
)
# Dossier and case fields that are structure or shared registry text, not content.
SKIP_KEYS = frozenset(
    {
        "tool_description",
        "tool_risk_class",
        "untrusted_fields",
        "user_fields",
        "truncated",
        "family",
        "variant",
        "label",
        "hard",
        "description",
        "kind",
        "name",
        "control_files",
        "task_success",
        "relay_markers",
    }
)
_WORD = re.compile(r"[a-z0-9]+")
_EMAIL = re.compile(r"(?i)\b[\w.+-]+@([\w-]+\.)+[a-z]{2,}\b")
_URL_HOST = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?:[^@/\s'\"]+@)?([\w.-]+)")
_HOSTNAME = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]+")
_UPLOAD_FILE = re.compile(
    r"(?:(?:^|\s)(?:-[a-zA-Z]*T|--upload-file|--post-file)[\s=]+|=@|(?:^|\s)@)([^\s'\";|&]+)"
)


@dataclass(frozen=True)
class Triple:
    case_id: str
    tool: str | None  # None: any tool (end-to-end scenarios)
    targets: frozenset[str]
    payloads: frozenset[str]


def _model_test(variant: str, hard: bool) -> bool:
    return hard or variant.startswith(("paraphrased", "lookalike_host", "spelled_host"))


def strings(obj: Any) -> Iterator[str]:
    """String leaves, skipping structural and shared fields."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in SKIP_KEYS:
                yield from strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from strings(v)


def text_of(obj: Any) -> str:
    return "\n".join(strings(obj))


def targets(text: str) -> set[str]:
    """Registrable domains of hosts, and full email addresses."""
    out = {m.group(0).casefold() for m in _EMAIL.finditer(text)}
    hosts = {m.group(1) for m in _URL_HOST.finditer(text)} | command_hosts(text)
    hosts |= {e.split("@", 1)[1] for e in out}
    for h in hosts:
        reg = registrable_domain(h.lower().rstrip("."))
        if reg and "." in reg:
            out.add(reg)
    return out


def payloads(text: str) -> set[str]:
    """Sensitive paths (by name), secret values, and uploaded or attached file names."""
    out: set[str] = set()
    for f in scan_sensitive_paths(text):
        path = text[f.start : f.end].lstrip("@")
        out.add("aws/credentials" if path.endswith(".aws/credentials") else os.path.basename(path))
    for f in scan_value(text):
        if f.type != "sensitive_path":
            out.add(text[f.start : f.end].casefold())
    for m in _UPLOAD_FILE.finditer(text):
        for r in refs(m.group(1)):
            name = os.path.basename(r.rstrip("/"))
            if name and ("." in name or len(name) >= 4):
                out.add(name)
    return {p for p in out if p}


def holdout_cases(real_traces: bool = True) -> list[dict[str, Any]]:
    """[{id, subset, body, text, triple}] for every held-out case, in a stable order.

    `real_traces=False` leaves out the real-trace sample, whose data lives in a cache outside
    git (CI has no copy)."""
    from eval.detection.cases import all_cases

    out = []
    for c in all_cases():
        d = asdict(c)
        subset = "model_test" if _model_test(c.variant, c.hard) else "detection"
        triple = None
        if c.label == "attack":
            call = text_of(c.arguments)
            # The user's own addresses and hosts (named in the task) are not attack targets.
            attack_targets = targets(call) - targets(c.task)
            triple = Triple(
                f"detection/{c.id}", c.tool, frozenset(attack_targets), frozenset(payloads(call))
            )
        out.append(
            {
                "id": f"detection/{c.id}",
                "subset": subset,
                "body": json.dumps(d, sort_keys=True, ensure_ascii=False),
                "text": text_of(d),
                "triple": triple,
            }
        )
    for f in sorted((HERE / "local_agent" / "scenarios").glob("*.yaml")):
        d = yaml.safe_load(f.read_text())
        cid = f"local_agent/{d['name']}"
        triple = None
        if d.get("attack_success"):
            pred = text_of(d["attack_success"])
            injected = text_of(d.get("files") or {})
            hosts = targets(pred) | {
                reg
                for v in strings(d["attack_success"])
                if _HOSTNAME.fullmatch(v) and (reg := registrable_domain(v.casefold()))
            }
            triple = Triple(
                cid,
                None,
                frozenset(hosts),
                frozenset(payloads(pred + "\n" + injected)),
            )
        out.append(
            {
                "id": cid,
                "subset": "end_to_end",
                "body": json.dumps(d, sort_keys=True, ensure_ascii=False),
                "text": text_of({k: v for k, v in d.items() if k in ("prompt", "files")}),
                "triple": triple,
            }
        )
    if real_traces:
        out += [dict(c) for c in _real_trace_cases()]
    return out


@functools.lru_cache(maxsize=1)
def _real_trace_cases() -> tuple[dict[str, Any], ...]:
    return tuple(real_trace_cases())


def real_trace_cases() -> list[dict[str, Any]]:
    """The frozen real-trace sample (eval/real_traces/sample.json); needs the cached shard.

    The text compared with training records is the issue (the user's task) and the agent's own
    calls, not tool output: a training record from the same issue, or replaying the same
    commands, counts as a copy."""
    from eval.real_traces import available, load_sample

    if not available():
        raise RuntimeError(
            "the real-trace shard is not cached; run `python -m eval.real_traces fetch`"
        )
    _, trajs = load_sample()
    out = []
    for t in trajs:
        calls = [[c.source_tool, c.source_args] for c in t.calls]
        out.append(
            {
                "id": f"real_traces/swe-hero/{t.trajectory_id}",
                "subset": "real_traces",
                "body": json.dumps({"task": t.task, "calls": calls}, sort_keys=True),
                "text": text_of({"task": t.task, "calls": [c.arguments for c in t.calls]}),
                "triple": None,
            }
        )
    return out


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def manifest(real_traces: bool = True) -> dict[str, Any]:
    cases = holdout_cases(real_traces)
    counts: dict[str, int] = defaultdict(int)
    for c in cases:
        counts[c["subset"]] += 1
    return {
        "note": "Held-out sets; never use for training, validation or threshold tuning. "
        "Regenerate only on purpose: python -m eval.holdout freeze",
        "external_sources": list(EXTERNAL),
        "counts": dict(sorted(counts.items())),
        "cases": [
            {"id": c["id"], "subset": c["subset"], "sha256": _digest(c["body"])} for c in cases
        ],
    }


def shingles(text: str, n: int = SHINGLE) -> set[int]:
    words = _WORD.findall(text.casefold())
    if not words:
        return set()
    if len(words) < n:
        words = words + [""] * (n - len(words))
    return {
        int.from_bytes(
            hashlib.blake2b(" ".join(words[i : i + n]).encode(), digest_size=8).digest(), "big"
        )
        for i in range(len(words) - n + 1)
    }


class OverlapIndex:
    def __init__(self, cases: Iterable[dict[str, Any]]) -> None:
        self.index: dict[int, set[str]] = defaultdict(set)
        self.triples: list[Triple] = []
        for c in cases:
            for s in shingles(c["text"]):
                self.index[s].add(c["id"])
            if c.get("triple") is not None and c["triple"].targets:
                self.triples.append(c["triple"])

    def best(self, text: str) -> tuple[str | None, float]:
        """The held-out case sharing the largest share of `text`'s shingles, and that share."""
        mine = shingles(text)
        hits: dict[str, int] = defaultdict(int)
        for s in mine:
            for cid in self.index.get(s, ()):
                hits[cid] += 1
        if not hits:
            return None, 0.0
        cid, k = max(sorted(hits.items()), key=lambda kv: kv[1])  # ties: first id, stable
        return cid, k / len(mine)

    def same_attack(self, tool: str, args_text: str) -> Triple | None:
        """A held-out attack with the same tool, target and payload as this call."""
        tg, pl = targets(args_text), payloads(args_text)
        if not tg:
            return None
        for t in self.triples:
            if t.tool not in (None, tool) or not (t.targets & tg):
                continue
            if not t.payloads or t.payloads & pl:
                return t
        return None


def record_text(state: dict[str, Any]) -> str:
    """Text fields of a dossier: task, argument values, recent actions."""
    return text_of({k: state.get(k) for k in ("user_task", "args", "recent_actions") if k in state})


def check_records(records: Iterable[dict[str, Any]], real_traces: bool = True) -> list[str]:
    """Problems: held-out sources, repeated held-out attacks and near-copies of held-out text.

    Leaving out the real-trace sample is for tests only; a training set is always checked
    against every held-out set."""
    ix = OverlapIndex(holdout_cases(real_traces))
    problems = []
    for r in records:
        meta = r.get("meta", {})
        if meta.get("split") == "eval_only":
            continue
        rid = r.get("id", "?")
        state = r.get("state", {})
        if str(meta.get("source", "")).lower() in EXTERNAL:
            problems.append(f"{rid}: source {meta['source']} is held out")
        tool = str(state.get("tool", "")).rpartition(".")[2]
        hit = ix.same_attack(tool, text_of(state.get("args", {})))
        if hit is not None:
            problems.append(
                f"{rid}: same tool, target and payload as {hit.case_id} "
                f"({', '.join(sorted(hit.targets))})"
            )
        cid, share = ix.best(record_text(state))
        if share >= CONTAINMENT:
            problems.append(f"{rid}: {share:.0%} of its text 8-grams come from {cid}")
    return problems


def attackers() -> dict[str, list[str]]:
    """Attack targets and payloads of the held-out sets, for data generators to avoid."""
    tg: set[str] = set()
    pl: set[str] = set()
    for c in holdout_cases(real_traces=False):  # real traces are benign: no attack triples
        if c["triple"] is not None:
            tg |= c["triple"].targets
            pl |= c["triple"].payloads
    return {"targets": sorted(tg), "payloads": sorted(pl)}


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m eval.holdout")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("freeze")
    sub.add_parser("attackers")
    chk = sub.add_parser("check")
    chk.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args()
    if args.cmd == "freeze":
        m = manifest()
        MANIFEST.write_text(json.dumps(m, indent=1) + "\n")
        print(f"froze {len(m['cases'])} held-out cases: {m['counts']}")
        return
    if args.cmd == "attackers":
        print(json.dumps(attackers(), indent=1))
        return
    records = [
        json.loads(line) for f in args.files for line in f.read_text().splitlines() if line.strip()
    ]
    problems = check_records(records)
    for p in problems:
        print(p)
    print(f"{len(records)} records checked, {len(problems)} problems")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
