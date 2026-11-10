"""Dossier assembly and truncation (FR-005, FR-008).

Shared with training/ so the training and inference formats can't drift.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from tainttrap.core.masking import placeholder_json, placeholder_text
from tainttrap.core.types import ArgumentProvenance, Dossier, Origin, RiskClass, ToolRegistryEntry

UNKNOWN_TASK = "(unknown task)"
TIER_BUDGETS = {"cpu-int8": 512, "gpu-fp16": 2048, "trt-fp16": 2048, "none": 2048}
TASK_MAX_TOKENS = 512
MIN_ARG_CHARS = 64

TokenCounter = Callable[[str], int]


def approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _shorten(s: str, keep: int) -> str:
    if len(s) <= keep:
        return s
    cut = len(s) - keep
    half = keep // 2
    return f"{s[:half]}…[truncated {cut} chars]…{s[-(keep - half) :]}"


def _longest_string(obj: Any, path: tuple[Any, ...] = ()) -> tuple[tuple[Any, ...], int]:
    best: tuple[tuple[Any, ...], int] = ((), -1)
    if isinstance(obj, str):
        return path, len(obj)
    items = (
        obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else ()
    )
    for k, v in items:
        cand = _longest_string(v, (*path, k))
        if cand[1] > best[1]:
            best = cand
    return best


def _set_at(obj: Any, path: tuple[Any, ...], value: Any) -> None:
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def to_state_text(d: Dossier) -> str:
    """Compact JSON serialization fed to the model and the judge."""
    return json.dumps(d.to_public(), ensure_ascii=False, separators=(",", ":"), sort_keys=False)


NOTES = {
    "details_evicted": "first seen in tool output; details evicted",
    "degraded": "session degraded; destination not provably trusted",
}


def build_dossier(
    *,
    task: str | None,
    tool: str,
    registry_entry: ToolRegistryEntry | None,
    risk_class: RiskClass,
    arguments: dict[str, Any],
    provenance: Sequence[ArgumentProvenance],
    recent_actions: Sequence[str],
    tier: str = "none",
    count_tokens: TokenCounter = approx_tokens,
) -> Dossier:
    budget = TIER_BUDGETS.get(tier, 2048)
    truncated = False

    task_text = placeholder_text(task) if task else UNKNOWN_TASK
    if count_tokens(task_text) > TASK_MAX_TOKENS:
        task_text = _shorten(task_text, TASK_MAX_TOKENS * 4)
        truncated = True

    args: dict[str, Any] = json.loads(json.dumps(placeholder_json(arguments), default=str))
    recent = list(recent_actions)[-8:]

    def make() -> Dossier:
        return Dossier(
            user_task=task_text,
            tool=tool,
            tool_description=registry_entry.description if registry_entry else "",
            tool_risk_class=risk_class,
            args=args,
            untrusted_fields=tuple(p.path for p in provenance if p.origin is Origin.UNTRUSTED),
            user_fields=tuple(p.path for p in provenance if p.origin is Origin.USER),
            provenance_notes=tuple(
                f"{p.path}: {NOTES[p.match_kind]}" for p in provenance if p.match_kind in NOTES
            )[:8],
            recent_actions=tuple(recent),
            truncated=truncated,
        )

    d = make()
    tokens = count_tokens(to_state_text(d))
    # Priority (kept longest): tool, risk class, provenance lists, argument start/end, task, recent.
    while tokens > budget:
        path, length = _longest_string(args)
        if path and length > MIN_ARG_CHARS:
            over_chars = (tokens - budget) * 4 + 64
            _set_at(
                args, path, _shorten(_get_at(args, path), max(MIN_ARG_CHARS, length - over_chars))
            )
        elif len(task_text) > 128:
            task_text = _shorten(task_text, max(128, len(task_text) // 2))
        elif recent:
            recent.pop(0)
        else:
            break
        truncated = True
        d = make()
        tokens = count_tokens(to_state_text(d))
    return d.model_copy(update={"token_estimate": tokens, "truncated": truncated})


def _get_at(obj: Any, path: tuple[Any, ...]) -> Any:
    for k in path:
        obj = obj[k]
    return obj
