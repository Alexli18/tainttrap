"""Policy loading and validation (FR-019..FR-022). Mirrors contracts/policy.schema.json."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tainttrap.core.types import FailureMode, Mode, Outcome, RiskClass

RiskAction = Literal["allow", "ask", "block", "escalate"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Thresholds(_Strict):
    aligned_block: float = Field(0.2, ge=0, le=1)
    aligned_allow: float = Field(0.8, ge=0, le=1)
    sensitive_block: float = Field(0.9, ge=0, le=1)
    needs_human_ask: float = Field(0.7, ge=0, le=1)

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if not self.aligned_block < self.aligned_allow:
            raise ValueError("thresholds.aligned_block must be < thresholds.aligned_allow")
        return self


class RiskActionCell(_Strict):
    aligned_high: Outcome
    aligned_mid: RiskAction


DEFAULT_RISK_ACTIONS: dict[RiskClass, RiskActionCell] = {
    RiskClass.READ_ONLY: RiskActionCell(aligned_high=Outcome.ALLOW, aligned_mid="allow"),
    RiskClass.WRITE_INTERNAL: RiskActionCell(aligned_high=Outcome.ALLOW, aligned_mid="escalate"),
    RiskClass.EXTERNAL_COMMUNICATION: RiskActionCell(
        aligned_high=Outcome.ALLOW, aligned_mid="escalate"
    ),
    RiskClass.DESTRUCTIVE: RiskActionCell(aligned_high=Outcome.ASK, aligned_mid="escalate"),
    RiskClass.FINANCIAL: RiskActionCell(aligned_high=Outcome.ASK, aligned_mid="block"),
    RiskClass.CREDENTIAL_ACCESS: RiskActionCell(aligned_high=Outcome.ASK, aligned_mid="block"),
    RiskClass.UNKNOWN: RiskActionCell(aligned_high=Outcome.ASK, aligned_mid="escalate"),
}


class SecretsRules(_Strict):
    enabled: bool = True
    high_confidence_action: Outcome = Outcome.BLOCK
    medium_confidence_action: Outcome = Outcome.ASK
    disabled_rules: tuple[str, ...] = ()


class DomainRules(_Strict):
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


class CommandRules(_Strict):
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    use_builtin_deny: bool = True

    @field_validator("allow", "deny")
    @classmethod
    def _compiles(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"invalid regex {pattern!r}: {e}") from e
        return v


class Rules(_Strict):
    secrets: SecretsRules = SecretsRules()
    domains: DomainRules = DomainRules()
    commands: CommandRules = CommandRules()
    untrusted_recipient_external: Outcome = Outcome.BLOCK


class Money(_Strict):
    amount: float = Field(ge=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")


class Budgets(_Strict):
    per_session: dict[RiskClass, int] = Field(
        default_factory=lambda: {
            RiskClass.FINANCIAL: 3,
            RiskClass.DESTRUCTIVE: 10,
            RiskClass.EXTERNAL_COMMUNICATION: 20,
        }
    )
    max_money_per_session: Money = Money(amount=100, currency="USD")
    exceeded_action: Literal["ask", "block"] = "ask"


class ModelSettings(_Strict):
    timeout_ms: int = Field(2000, ge=50)
    tier: Literal["auto", "cpu-int8", "gpu-fp16", "trt-fp16"] = "auto"
    enabled: bool = True


class JudgeSettings(_Strict):
    enabled: bool = False
    provider: Literal["openai_compatible", "anthropic"] | None = None
    endpoint: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    allow_remote: bool = False
    timeout_ms: int = Field(15000, ge=500)

    @model_validator(mode="after")
    def _complete(self) -> JudgeSettings:
        if not self.enabled:
            return self
        if not (self.provider and self.endpoint and self.model):
            raise ValueError(
                "judge.enabled requires judge.provider, judge.endpoint and judge.model"
            )
        if not _is_loopback(self.endpoint) and not self.allow_remote:
            raise ValueError(
                "judge.endpoint is not a loopback address; set judge.allow_remote: true to send "
                "dossiers off this machine"
            )
        return self


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class HumanSettings(_Strict):
    timeout_s: int = Field(60, ge=5, le=3600)
    channel: Literal["terminal"] = "terminal"


class ProvenanceSettings(_Strict):
    min_fragment_len: int = Field(24, ge=12, le=64)
    min_entity_len: int = Field(6, ge=4)


class HookSettings(_Strict):
    explicit_allow: bool = False
    # claude_code: return "ask" and let Claude Code's own dialog decide (TaintTrap never sees the
    # answer). daemon: wait for a code-confirmed approval in the daemon queue instead, so the
    # approval is explicit and approved recipients can be remembered.
    approval_channel: Literal["claude_code", "daemon"] = "claude_code"


class ProxySettings(_Strict):
    task_ttl_min: int = Field(30, ge=1)


class LoggingSettings(_Strict):
    retain_days: int = Field(90, ge=1)


class Policy(_Strict):
    version: Literal[1] = 1
    mode: Mode = Mode.OBSERVE
    thresholds: Thresholds = Thresholds()
    risk_actions: dict[RiskClass, RiskActionCell] = Field(
        default_factory=lambda: dict(DEFAULT_RISK_ACTIONS)
    )
    rules: Rules = Rules()
    budgets: Budgets = Budgets()
    failure_mode: FailureMode = FailureMode.FAIL_OPEN
    fail_closed_action: Literal["ask", "block"] = "ask"
    model: ModelSettings = ModelSettings()
    judge: JudgeSettings = JudgeSettings()
    human: HumanSettings = HumanSettings()
    provenance: ProvenanceSettings = ProvenanceSettings()
    hook: HookSettings = HookSettings()
    proxy: ProxySettings = ProxySettings()
    logging: LoggingSettings = LoggingSettings()
    telemetry: Literal[False] = False

    @field_validator("risk_actions")
    @classmethod
    def _fill_defaults(cls, v: dict[RiskClass, RiskActionCell]) -> dict[RiskClass, RiskActionCell]:
        return {**DEFAULT_RISK_ACTIONS, **v}

    def action_for(self, risk: RiskClass) -> RiskActionCell:
        return self.risk_actions.get(risk, DEFAULT_RISK_ACTIONS[RiskClass.UNKNOWN])


class PolicyError(ValueError):
    """Raised with one message per invalid field, each naming the field path."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def default_policy_text() -> str:
    return resources.files("tainttrap.data").joinpath("default-policy.yaml").read_text()


def parse_policy(data: Any) -> Policy:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(["<root>: policy must be a mapping"])
    try:
        return Policy.model_validate(data)
    except ValidationError as e:
        problems = []
        for err in e.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "<root>"
            problems.append(f"{loc}: {err['msg']}")
        raise PolicyError(problems) from None


def load_policy(path: Path | None = None) -> Policy:
    """Load a policy file; with no path (or a missing file) the packaged default applies."""
    if path is None or not path.exists():
        return parse_policy(yaml.safe_load(default_policy_text()))
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise PolicyError([f"<yaml>: {e}"]) from None
    return parse_policy(data)


def validate_file(path: Path) -> list[str]:
    try:
        load_policy(path)
    except PolicyError as e:
        return e.problems
    return []


def policy_hash(policy: Policy) -> str:
    canonical = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
