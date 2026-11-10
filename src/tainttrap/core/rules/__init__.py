"""Rule set evaluated before the model; the first final `block` wins, then final `ask`."""

from __future__ import annotations

from tainttrap.core.policy import Policy
from tainttrap.core.rules.base import (
    CallContext,
    LocalFileUpload,
    Rule,
    SecretToExternal,
    UntrustedRecipientExternal,
)
from tainttrap.core.types import RuleResult

_ORDER = {"block": 0, "ask": 1, "allow": 2, "none": 3}


def default_rules() -> list[Rule]:
    from tainttrap.core.rules.self_protect import SelfProtect

    return [SelfProtect(), SecretToExternal(), UntrustedRecipientExternal(), LocalFileUpload()]


def evaluate_all(rules: list[Rule], ctx: CallContext, policy: Policy) -> list[RuleResult]:
    results = []
    for rule in rules:
        r = rule.evaluate(ctx, policy)
        if r is not None:
            results.append(r)
    return results


def final_verdict(results: list[RuleResult]) -> RuleResult | None:
    finals = [r for r in results if r.final and r.verdict in ("block", "ask")]
    return min(finals, key=lambda r: _ORDER[r.verdict]) if finals else None


__all__ = ["CallContext", "default_rules", "evaluate_all", "final_verdict"]
