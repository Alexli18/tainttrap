"""Entities and enums from specs/001-tainttrap-mvp/data-model.md."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskClass(StrEnum):
    READ_ONLY = "read_only"
    WRITE_INTERNAL = "write_internal"
    EXTERNAL_COMMUNICATION = "external_communication"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    CREDENTIAL_ACCESS = "credential_access"
    # Only for tools missing from the registry; the model never outputs it.
    UNKNOWN = "unknown"


MODEL_RISK_CLASSES: tuple[RiskClass, ...] = tuple(
    r for r in RiskClass if r is not RiskClass.UNKNOWN
)


class Origin(StrEnum):
    USER = "user"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"
    LITERAL = "literal"


class Outcome(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


class Mode(StrEnum):
    OBSERVE = "observe"
    SOFT = "soft"
    STRICT = "strict"


class DecidedBy(StrEnum):
    RULES = "rules"
    MODEL = "model"
    JUDGE = "judge"
    HUMAN = "human"
    FAILURE_MODE = "failure_mode"
    POLICY_DEFAULT = "policy_default"


class FailureMode(StrEnum):
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class Adapter(StrEnum):
    CLAUDE_CODE_HOOK = "claude_code_hook"
    MCP_PROXY = "mcp_proxy"
    SDK = "sdk"


def utcnow() -> datetime:
    return datetime.now(UTC)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UserTask(_Frozen):
    session_id: str
    text: str
    history: tuple[str, ...] = Field(default=(), max_length=5)
    source: Literal["hook_prompt", "proxy_config", "proxy_tool", "none"] = "hook_prompt"
    updated_at: datetime = Field(default_factory=utcnow)


class ToolCall(_Frozen):
    call_id: str
    session_id: str
    adapter: Adapter
    tool_name: str
    server: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime = Field(default_factory=utcnow)


class ArgRule(_Frozen):
    arg: str
    pattern: str
    risk_class: RiskClass


class ToolRegistryEntry(_Frozen):
    name: str
    server: str | None = None
    description: str = Field(max_length=300)
    risk_class: RiskClass
    arg_risk_overrides: tuple[ArgRule, ...] = ()
    sensitive_args: tuple[str, ...] = ()
    source: Literal["builtin", "user"] = "builtin"
    # Who can write the data this tool returns. first_party: the user's own address book;
    # third_party: anything an outsider can put data into (web, inbox, CRM, repositories).
    output_trust: Literal["first_party", "third_party"] = "third_party"

    @field_validator("risk_class")
    @classmethod
    def _not_unknown(cls, v: RiskClass) -> RiskClass:
        if v is RiskClass.UNKNOWN:
            raise ValueError("registry entries cannot have risk_class 'unknown'")
        return v


class ArgumentProvenance(_Frozen):
    path: str
    origin: Origin
    matched_call_ids: tuple[str, ...] = ()
    match_kind: (
        Literal[
            "exact",
            "substring",
            "base64",
            "url",
            "case_folded",
            "entity",
            "details_evicted",  # first seen in tool output, record evicted (T145 follow-up)
            "degraded",  # degraded scope, destination not provably trusted
        ]
        | None
    ) = None
    match_len: int = 0


class Dossier(_Frozen):
    user_task: str
    tool: str
    tool_description: str = Field(default="", max_length=300)
    tool_risk_class: RiskClass
    args: dict[str, Any]
    untrusted_fields: tuple[str, ...] = ()
    user_fields: tuple[str, ...] = ()
    recent_actions: tuple[str, ...] = Field(default=(), max_length=8)
    truncated: bool = False
    # e.g. "args.to: first seen in tool output; details evicted" (T145 follow-up)
    provenance_notes: tuple[str, ...] = Field(default=(), max_length=8)
    token_estimate: int = 0

    def to_public(self) -> dict[str, Any]:
        """Serialization matching contracts/dossier.schema.json."""
        return self.model_dump(mode="json", exclude={"token_estimate"})


class RuleResult(_Frozen):
    rule_id: str
    verdict: Literal["block", "ask", "allow", "none"]
    final: bool = False
    evidence: str = ""
    severity: Literal["info", "warn", "critical"] = "info"
    reason_codes: tuple[str, ...] = ()


class Assessment(_Frozen):
    aligned: float = Field(ge=0.0, le=1.0)
    risk: RiskClass
    risk_probs: dict[RiskClass, float] = Field(default_factory=dict)
    sensitive_data: float = Field(ge=0.0, le=1.0)
    needs_human: float = Field(ge=0.0, le=1.0)
    source: Literal["model", "judge"] = "model"
    model_id: str = ""
    latency_ms: float = 0.0
    rationale: str | None = Field(default=None, max_length=400)

    @field_validator("risk")
    @classmethod
    def _model_risk(cls, v: RiskClass) -> RiskClass:
        if v is RiskClass.UNKNOWN:
            raise ValueError("assessments cannot output risk 'unknown'")
        return v

    @field_validator("risk_probs")
    @classmethod
    def _sums_to_one(cls, v: dict[RiskClass, float]) -> dict[RiskClass, float]:
        if v and abs(sum(v.values()) - 1.0) > 1e-6:
            raise ValueError("risk_probs must sum to 1")
        return v


class Escalation(_Frozen):
    to: Literal["judge", "human"]
    result: str
    latency_ms: float = 0.0


class Decision(_Frozen):
    call_id: str
    outcome: Outcome
    enforced: bool
    effective_outcome: Outcome
    decided_by: DecidedBy
    reason: str = Field(max_length=300)
    reason_codes: tuple[str, ...] = ()
    # Block only, for the agent: which part of a compound command was blocked; do not relay.
    hint: str = Field(default="", max_length=700)
    # Block only, for the human: the blocked command part(s), masked.
    blocked_parts: tuple[str, ...] = ()
    escalations: tuple[Escalation, ...] = ()
    latency_ms: float = 0.0
    entry_id: str = ""


class MistakeFlag(_Frozen):
    entry_id: str
    flagged_at: datetime = Field(default_factory=utcnow)
    correct_outcome: Outcome
    correct_labels: dict[str, Any] = Field(default_factory=dict)
    note: str = ""
