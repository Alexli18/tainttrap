"""Provenance-based stand-in for the fine-tuned model.

Used until a verified Laya artifact is installed, so rules-only installs still tell
"the user asked for this" apart from "this came from a tool response". It never claims
high confidence that an action is *misaligned*; that is left to rules, the model and the judge.
"""

from __future__ import annotations

from tainttrap.core.dossier import UNKNOWN_TASK
from tainttrap.core.rules.base import DESTINATION_KEYS, SHELL_ARGS
from tainttrap.core.types import Assessment, Dossier, RiskClass

CONTROL_KEYS = DESTINATION_KEYS | set(SHELL_ARGS) | {"path", "file_path", "method", "amount"}

ALIGNED_IF_CLEAN = 0.85
UNSURE = 0.5


class HeuristicProvider:
    model_id = "heuristic-v0"

    async def assess(self, dossier: Dossier) -> Assessment:
        risk = dossier.tool_risk_class
        if risk is RiskClass.UNKNOWN:
            risk = RiskClass.WRITE_INTERNAL
        has_secret = "<SECRET:" in str(dossier.args)
        # Content copied from tool output (an email body, a summary) is normal; a destination,
        # command or path that came from tool output is what injections steer.
        steered = any(_key(p) in CONTROL_KEYS for p in dossier.untrusted_fields)
        if dossier.user_task == UNKNOWN_TASK or steered:
            aligned = UNSURE
        else:
            aligned = ALIGNED_IF_CLEAN
        return Assessment(
            aligned=aligned,
            risk=risk,
            risk_probs={risk: 1.0},
            sensitive_data=0.95 if has_secret else 0.05,
            needs_human=0.5 if aligned == UNSURE else 0.1,
            source="model",
            model_id=self.model_id,
        )


def _key(path: str) -> str:
    parts = [p for p in path.split(".")[1:] if not p.isdigit()]
    return parts[-1].lower() if parts else ""
