"""The decision state machine (data-model.md "Decision state machine" and "Mode semantics")."""

from __future__ import annotations

import asyncio
import dataclasses
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from tainttrap.core.advice import (
    EXFIL_CODES,
    MAX_PARTS,
    NO_RELAY,
    compound_hint,
    probe_commands,
    split_compound,
)
from tainttrap.core.domains import host_known
from tainttrap.core.dossier import build_dossier, to_state_text
from tainttrap.core.expand import expand_arguments
from tainttrap.core.judge.base import Judge, JudgeVerdict
from tainttrap.core.masking import mask_json, mask_text
from tainttrap.core.model.base import AssessmentProvider, ModelUnavailable
from tainttrap.core.model.heuristic import HeuristicProvider
from tainttrap.core.policy import Policy, policy_hash
from tainttrap.core.provenance import (
    ProvenanceIndex,
    extract_entities,
    normalize,
    redact_secrets,
)
from tainttrap.core.registry import SEVERITY, Registry
from tainttrap.core.rules import CallContext, evaluate_all, final_verdict
from tainttrap.core.rules.base import (
    _NETWORK_HINTS,
    ADDRESSEE_KEYS,
    SHELL_ARGS,
    Rule,
    addressee_values,
)
from tainttrap.core.rules.secrets import SecretFinding, iter_strings, map_strings, scan_arguments
from tainttrap.core.taint import matches, propagate
from tainttrap.core.types import (
    Adapter,
    ArgumentProvenance,
    Assessment,
    DecidedBy,
    Decision,
    Escalation,
    FailureMode,
    Mode,
    Origin,
    Outcome,
    RiskClass,
    RuleResult,
    utcnow,
)

RawOutcome = Literal["allow", "ask", "block", "escalate"]
# Commands that reach the network besides the obvious clients (_NETWORK_HINTS): package
# installs and git remotes. Used only to keep soft mode asking about them (_soft_local_waiver).
_REMOTE_COMMANDS = re.compile(
    r"\b(?:pip3?|uv|poetry|pipenv|conda|npm|pnpm|yarn|gem|cargo|go|apt(?:-get)?|brew|dnf|yum)"
    r"\s+(?:\S+\s+)?(?:install|add|get|update|upgrade|sync|fetch|download)\b"
    r"|\bgit\s+(?:clone|fetch|pull|push|ls-remote|submodule\s+update|remote\s+add)\b"
)
# Where a raw `block` came from; soft mode only enforces the first two.
BlockSource = Literal["rule", "aligned_below_block", "table"]

REASON_TEXT = {
    "self_protect": "it would modify or stop TaintTrap itself",
    "secret_in_args": "the arguments contain secret data going out",
    "possible_secret_in_args": "the arguments may contain secret data",
    "untrusted_recipient": "data goes to a destination that came from tool output, not from you",
    "recipient_from_directory": (
        "the recipient came from the address book; confirm it is the right person"
    ),
    "upload_unknown_host": "it uploads a local file to a host that is not in your task",
    "provenance_degraded": (
        "the session's earlier records are gone, so the destination is not trusted"
    ),
    "task_mismatch": "it does not match the task",
    "unknown_tool": "the tool is not in the trusted registry",
    "model_unavailable": "the checker model is unavailable",
    "unknown_task": "the user's task is unknown",
    "sensitive_data": "it sends sensitive data",
    "needs_human": "the checker recommends a human look",
}


@dataclass
class CheckRequest:
    adapter: Adapter
    session_id: str
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    server: str | None = None
    cwd: str | None = None
    task_hint: str | None = None
    deadline_ms: int | None = None


@dataclass
class SessionView:
    """What the engine needs from daemon session state."""

    task: str | None
    task_history: Sequence[str] = ()
    recent_actions: Sequence[str] = ()
    scope_ids: Sequence[str] = ()


@dataclass
class EngineResult:
    decision: Decision
    log_entry: dict[str, Any]


@dataclass
class Engine:
    registry: Registry
    provenance: ProvenanceIndex
    provider: AssessmentProvider
    rules: list[Rule]
    tier: str = "none"
    judge: Judge | None = None
    known_recipients: set[str] = field(default_factory=set)
    shadow: AssessmentProvider | None = None
    _shadow_tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    async def decide(
        self, req: CheckRequest, session: SessionView, policy: Policy, probe: bool = False
    ) -> EngineResult:
        """`probe=True` checks one part of a blocked compound command: no judge, no shadow."""
        t0 = time.perf_counter()
        if not probe:
            self.provenance.note_check(session.scope_ids, req.call_id)
        deadline = (req.deadline_ms or 30_000) / 1000
        # Task runners (make/npm/just) are expanded one level so the real commands are visible.
        arguments = expand_arguments(req.arguments, req.cwd)
        lookup_args = arguments
        if "expanded_command" in arguments:
            combined = f"{arguments.get('command', '')} ; {arguments['expanded_command']}"
            lookup_args = {**arguments, "command": combined}
        entry, risk = self.registry.lookup(req.tool_name, req.server, lookup_args)
        task = session.task or req.task_hint
        secrets = (
            scan_arguments(arguments, frozenset(policy.rules.secrets.disabled_rules))
            if policy.rules.secrets.enabled
            else {}
        )
        # A secret seen earlier in tool output counts in any case or URL/base64 encoding.
        observed, known_secrets = self.provenance.observed_secrets(session.scope_ids, arguments)
        dossier_args = arguments
        if observed:
            if policy.rules.secrets.enabled:
                for path in observed:
                    secrets.setdefault(path, []).append(
                        SecretFinding("observed-secret", "high", 0, 0, "observed_secret")
                    )
            dossier_args = map_strings(
                arguments,
                lambda path, v: (
                    redact_secrets(v, known_secrets, "<SECRET:observed_secret>")
                    if path in observed
                    else v
                ),
            )
        # Files copied from sensitive ones count as sensitive (taint.py); new copies are recorded
        # once the call is not blocked.
        derived = self.provenance.derived_files(session.scope_ids)
        shell_key = next((k for k in SHELL_ARGS if isinstance(arguments.get(k), str)), None)
        new_derived: set[str] = set()
        derived_hits: list[str] = []
        if shell_key:
            new_derived, reads = propagate(str(lookup_args[shell_key]), derived)
            if reads:
                derived_hits.append(f"args.{shell_key}")
        if derived:
            derived_hits += [
                path
                for path, v in iter_strings(arguments)
                if path != f"args.{shell_key}" and matches(v, derived)
            ]
        if policy.rules.secrets.enabled:
            for path in derived_hits:
                secrets.setdefault(path, []).append(
                    SecretFinding("derived-sensitive-file", "high", 0, 0, "derived_sensitive_file")
                )
        texts = [t for t in (task, *session.task_history) if t]
        prov = self.provenance.label(session.scope_ids, texts, arguments)
        tool_key = f"{req.server}.{req.tool_name}" if req.server else req.tool_name
        prov = self._trust_known_recipients(prov, arguments, tool_key)
        if self.provenance.degraded(session.scope_ids):
            prov = self._degraded_labels(prov, arguments, texts, policy, session)
        dossier = build_dossier(
            task=task,
            tool=req.tool_name if not req.server else f"{req.server}.{req.tool_name}",
            registry_entry=entry,
            risk_class=risk,
            arguments=dossier_args,
            provenance=prov,
            recent_actions=session.recent_actions,
            tier=self.tier,
        )
        ctx = CallContext(
            tool_name=req.tool_name,
            server=req.server,
            arguments=arguments,
            risk_class=risk,
            provenance=prov,
            secrets=secrets,
            task_text=task,
            extra={"cwd": req.cwd, **self._recipient_context(arguments, prov, session, tool_key)},
        )
        rule_results = evaluate_all(self.rules, ctx, policy)
        final_rule = final_verdict(rule_results)
        degraded_paths = [p.path for p in prov if p.match_kind in ("degraded", "details_evicted")]

        assessment: Assessment | None = None
        waived = False
        model_error: str | None = None
        reason_codes: list[str] = []
        decided_by: DecidedBy
        raw: RawOutcome
        block_source: BlockSource | None = None

        if final_rule is not None:
            raw = final_rule.verdict  # type: ignore[assignment]
            decided_by = DecidedBy.RULES
            block_source = "rule"
            for r in rule_results:
                if r.final:
                    reason_codes += r.reason_codes
            # Enrich the reason only (US1 AS-1); never changes the outcome.
            assessment, _ = await self._assess(
                dossier, min(policy.model.timeout_ms / 1000, deadline / 2)
            )
            if assessment and assessment.aligned < policy.thresholds.aligned_allow:
                reason_codes.append("task_mismatch")
        else:
            assessment, model_error = await self._assess(
                dossier, min(policy.model.timeout_ms / 1000, deadline)
            )
            if assessment is None:
                decided_by = DecidedBy.FAILURE_MODE
                reason_codes.append("model_unavailable")
                if policy.failure_mode is FailureMode.FAIL_OPEN:
                    raw = "allow"
                else:
                    raw = policy.fail_closed_action
            else:
                decided_by = DecidedBy.MODEL
                raw, block_source, codes = self._from_assessment(
                    assessment, risk, policy, task, entry is None
                )
                if self._soft_local_waiver(
                    raw, codes, assessment, risk, policy, secrets, lookup_args
                ):
                    raw, codes, waived = "allow", [], True
                reason_codes += codes
            # Non-final rule results (e.g. a medium-confidence secret) can only tighten.
            for r in rule_results:
                if r.verdict == "ask" and raw == "allow":
                    raw = "ask"
                    decided_by = DecidedBy.RULES
                    reason_codes += r.reason_codes

        if degraded_paths and any(
            c in reason_codes for c in ("untrusted_recipient", "secret_in_args")
        ):
            # Say why the destination counts as untrusted without a record of where it came from.
            reason_codes.append("provenance_degraded")
        judge_out: dict[str, Any] = {}
        escalations: tuple[Escalation, ...] = ()
        reason_override: str | None = None
        if probe and raw == "escalate":
            outcome = Outcome.ASK
        else:
            outcome, decided_by, escalations, reason_override = await self._apply_mode(
                raw, block_source, decided_by, req, dossier, policy, reason_codes, judge_out
            )
        enforced = policy.mode is not Mode.OBSERVE
        reason = reason_override or self._reason(outcome, reason_codes, risk, req.tool_name)
        if outcome is Outcome.ALLOW and not probe:
            # Only an allowed call vouches for its arguments; a blocked or asked one (a human may
            # still say no) does not.
            values = dict(iter_strings(req.arguments))
            self.provenance.remember_trusted(
                session.scope_ids,
                req.call_id,
                (
                    values[p.path]
                    for p in prov
                    if p.origin is not Origin.UNTRUSTED and p.path in values
                ),
            )
        runs = outcome is not Outcome.BLOCK or policy.mode is Mode.OBSERVE
        if new_derived and runs and not probe:
            self.provenance.add_derived(session.scope_ids, new_derived)
        hint, blocked_parts = "", list[str]()
        if outcome is Outcome.BLOCK and not probe:

            def clean(v: str) -> str:
                return mask_text(redact_secrets(v, known_secrets, "<SECRET>"))

            hint, blocked_parts = await self._compound_hint(req, session, policy, clean)
            if not blocked_parts and (cmd := _shell_arg(req.arguments)):
                blocked_parts = [clean(cmd)[:120]]
            if EXFIL_CODES & set(reason_codes):
                hint = f"{hint} {NO_RELAY}".strip()
        decision = Decision(
            call_id=req.call_id,
            outcome=outcome,
            enforced=enforced,
            effective_outcome=outcome if enforced else Outcome.ALLOW,
            decided_by=decided_by,
            reason=mask_text(reason)[:300],
            reason_codes=tuple(dict.fromkeys(reason_codes)),
            hint=hint[:700],
            blocked_parts=tuple(blocked_parts),
            escalations=escalations,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        log_entry = {
            "kind": "decision",
            "session_id": req.session_id,
            "adapter": req.adapter.value,
            "mode": policy.mode.value,
            "policy_hash": policy_hash(policy),
            "model_version": assessment.model_id
            if assessment
            else getattr(self.provider, "model_id", None),
            "device_tier": self.tier,
            "call": {"call_id": req.call_id, "tool_name": req.tool_name, "server": req.server},
            "dossier": mask_json(dossier.to_public()),
            "provenance": [
                {
                    "path": p.path,
                    "origin": p.origin.value,
                    "match_kind": p.match_kind,
                    "match_len": p.match_len,
                }
                for p in prov
            ],
            "rule_results": [_rule_json(r) for r in rule_results],
            "decision": {
                "outcome": decision.outcome.value,
                "enforced": decision.enforced,
                "effective_outcome": decision.effective_outcome.value,
                "decided_by": decision.decided_by.value,
                "reason": decision.reason,
                "reason_codes": list(decision.reason_codes),
                "latency_ms": round(decision.latency_ms, 2),
            },
        }
        if decision.hint:
            log_entry["decision"]["hint"] = decision.hint
        if waived:
            log_entry["detail"] = "soft mode: heuristic task mismatch on a local command not asked"

        if escalations:
            log_entry["escalations"] = [
                {"to": e.to, "result": e.result, "latency_ms": round(e.latency_ms, 2)}
                for e in escalations
            ]
        if judge_out.get("verdict") is not None:
            verdict, judge_id, judge_ms = (
                judge_out["verdict"],
                judge_out["model_id"],
                judge_out["ms"],
            )
            if verdict is not None:
                log_entry["judge_assessment"] = {
                    "aligned": round(verdict.aligned, 4),
                    "risk": dossier.tool_risk_class.value,
                    "sensitive_data": 0.0,
                    "needs_human": 1.0 if verdict.decision == "ask" else 0.0,
                    "model_id": judge_id,
                    "latency_ms": round(judge_ms, 2),
                    "rationale": mask_text(verdict.reason)[:400],
                }
        if assessment:
            log_entry["assessment"] = _assessment_json(assessment)
        if model_error:
            log_entry["detail"] = mask_text(model_error)[:300]
        if self.shadow is not None and not probe:
            self._run_shadow(dossier, log_entry)
        return EngineResult(decision, log_entry)

    async def _compound_hint(
        self,
        req: CheckRequest,
        session: SessionView,
        policy: Policy,
        clean: Callable[[str], str],
    ) -> tuple[str, list[str]]:
        """Check each part of a blocked compound shell command on its own (advice.py)."""
        key = next((k for k in SHELL_ARGS if isinstance(req.arguments.get(k), str)), None)
        if key is None:
            return "", []
        parts = split_compound(req.arguments[key])
        probes = probe_commands(parts)
        if len(parts) < 2 or not probes or len(probes) > MAX_PARTS:
            return "", []
        outcomes: dict[int, str] = {}
        for i, sub in probes:
            sub_req = dataclasses.replace(req, arguments={**req.arguments, key: sub})
            res = await self.decide(sub_req, session, policy, probe=True)
            outcomes[i] = res.decision.outcome.value
        return compound_hint(parts, outcomes, clean)

    def _degraded_labels(
        self,
        prov: list[ArgumentProvenance],
        arguments: dict[str, Any],
        texts: Sequence[str],
        policy: Policy,
        session: SessionView,
    ) -> list[ArgumentProvenance]:
        """Degraded scope (the evicted-destination filter overflowed): absence of a record no
        longer means trust. A value carrying a destination that is not in the task, not in
        `rules.domains.allow` and not from an earlier trusted argument is untrusted."""
        task_norm = normalize(" ".join(texts))
        allow = policy.rules.domains.allow
        values = dict(iter_strings(arguments))
        out = []
        for p in prov:
            v = values.get(p.path)
            if p.origin is not Origin.UNTRUSTED and v is not None:
                for e in extract_entities(v, self.provenance.min_entity_len):
                    if e in task_norm or self.provenance.proven_trusted_entity(
                        session.scope_ids, e
                    ):
                        continue
                    host = e.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
                    if "." in host and host_known(host, None, allow):
                        continue
                    p = ArgumentProvenance(
                        path=p.path, origin=Origin.UNTRUSTED, match_kind="degraded"
                    )
                    break
            out.append(p)
        return out

    def _trust_known_recipients(
        self, prov: list[ArgumentProvenance], arguments: dict[str, Any], tool_key: str
    ) -> list[ArgumentProvenance]:
        """A recipient the human already approved counts as user-provided, even when it was
        looked up through a tool."""
        if not self.known_recipients:
            return prov
        values = dict(iter_strings(arguments))
        out = []
        for p in prov:
            v = values.get(p.path, "")
            if (
                p.origin is Origin.UNTRUSTED
                and _addressee_path(p.path)
                and f"{tool_key}\t{v.strip().casefold()}" in self.known_recipients
            ):
                p = ArgumentProvenance(path=p.path, origin=Origin.USER)
            out.append(p)
        return out

    def _recipient_context(
        self, arguments: dict[str, Any], prov: Sequence[Any], session: SessionView, tool_key: str
    ) -> dict[str, Any]:
        """Trust tier of the tools the untrusted recipients came from, plus known recipients."""
        call_ids = {
            cid
            for p in prov
            if p.origin.value == "untrusted" and _addressee_path(p.path)
            for cid in p.matched_call_ids
        }
        trust = "third_party"
        if call_ids:
            sources = self.provenance.source_tools(session.scope_ids, call_ids)
            tiers = set()
            for src in sources:
                server, _, tool = (src or "").rpartition(".")
                entry = self.registry.find(tool, server or None) if src else None
                if entry is None and server:
                    entry = self.registry.find(tool, None)
                tiers.add(entry.entry.output_trust if entry else "third_party")
            if tiers == {"first_party"}:
                trust = "first_party"
        return {
            "recipients": addressee_values(arguments),
            "recipient_trust": trust,
            "known_recipients": {
                k.split("\t", 1)[1]
                for k in self.known_recipients
                if k.split("\t", 1)[0] == tool_key
            },
        }

    async def _assess(self, dossier: Any, timeout: float) -> tuple[Assessment | None, str | None]:
        t = time.perf_counter()
        try:
            a = await asyncio.wait_for(self.provider.assess(dossier), timeout=max(timeout, 0.05))
        except ModelUnavailable as e:
            return None, f"model unavailable: {e}"
        except TimeoutError:
            return None, "model timeout"
        except Exception as e:  # noqa: BLE001 - a crashing model must not crash the check
            return None, f"model error: {type(e).__name__}: {e}"
        if not a.latency_ms:
            a = a.model_copy(update={"latency_ms": (time.perf_counter() - t) * 1000})
        return a, None

    @staticmethod
    def _soft_local_waiver(
        raw: str,
        codes: Sequence[str],
        a: Assessment,
        risk: RiskClass,
        policy: Policy,
        secrets: dict[str, list[SecretFinding]],
        arguments: dict[str, Any],
    ) -> bool:
        """Soft mode does not ask about a local shell command only because the provenance
        heuristic is unsure (2026-10-11): on real coding work that question fired on two calls
        in three. The command must be local (no network, package install or git remote), not
        destructive or credential-related by the registry, and carry no secret. Strict mode and
        a trained model keep asking."""
        cmd = _shell_arg(arguments)
        if policy.mode is not Mode.SOFT or raw not in ("ask", "escalate") or cmd is None:
            return False
        if a.model_id != HeuristicProvider.model_id or secrets:
            return False
        if risk not in (RiskClass.READ_ONLY, RiskClass.WRITE_INTERNAL):
            return False
        if not set(codes) <= {"task_mismatch", "needs_human", f"policy_ask_{risk.value}"}:
            return False  # e.g. unknown task or unknown tool: still asked
        expanded = arguments.get("expanded_command")
        full = f"{cmd} ; {expanded}" if isinstance(expanded, str) else cmd
        return not (_NETWORK_HINTS.search(full) or _REMOTE_COMMANDS.search(full))

    @staticmethod
    def _from_assessment(
        a: Assessment,
        registry_risk: RiskClass,
        policy: Policy,
        task: str | None,
        unknown_tool: bool,
    ) -> tuple[RawOutcome, BlockSource | None, list[str]]:
        th = policy.thresholds
        codes: list[str] = []
        risk = registry_risk
        if unknown_tool:
            codes.append("unknown_tool")
        elif SEVERITY[a.risk] > SEVERITY[registry_risk]:
            risk = a.risk
        if not task:
            codes.append("unknown_task")
        if a.aligned < th.aligned_block:
            return "block", "aligned_below_block", [*codes, "task_mismatch"]
        if a.sensitive_data >= th.sensitive_block and risk is RiskClass.EXTERNAL_COMMUNICATION:
            return "block", "table", [*codes, "sensitive_data"]
        cell = policy.action_for(RiskClass.UNKNOWN if unknown_tool else risk)
        # An unknown task never counts as confidently aligned (research R-04).
        if a.aligned >= th.aligned_allow and task:
            raw: RawOutcome = cell.aligned_high.value
        else:
            raw = cell.aligned_mid
            if raw != "allow":
                codes.append("task_mismatch" if task else "unknown_task")
        if raw == "allow" and a.needs_human >= th.needs_human_ask:
            raw = "ask"
            codes.append("needs_human")
        if raw in ("ask", "escalate") and not any(c.startswith("policy_ask") for c in codes):
            codes.append(f"policy_ask_{risk.value}")
        return raw, ("table" if raw == "block" else None), codes

    async def _apply_mode(
        self,
        raw: RawOutcome,
        block_source: BlockSource | None,
        decided_by: DecidedBy,
        req: CheckRequest,
        dossier: Any,
        policy: Policy,
        reason_codes: list[str],
        judge_out: dict[str, Any],
    ) -> tuple[Outcome, DecidedBy, tuple[Escalation, ...], str | None]:
        mode = policy.mode
        if raw == "block":
            if mode is Mode.SOFT and block_source == "table":
                return Outcome.ASK, decided_by, (), None
            return Outcome.BLOCK, decided_by, (), None
        if raw == "escalate":
            if mode is Mode.STRICT:
                return await self._escalate(req, dossier, policy, reason_codes, judge_out)
            # soft: straight to a human, never the judge; observe: recorded as a would-be ask.
            return (
                Outcome.ASK,
                decided_by if decided_by is not DecidedBy.MODEL else DecidedBy.POLICY_DEFAULT,
                (),
                None,
            )
        return Outcome(raw), decided_by, (), None

    async def _escalate(
        self,
        req: CheckRequest,
        dossier: Any,
        policy: Policy,
        reason_codes: list[str],
        judge_out: dict[str, Any],
    ) -> tuple[Outcome, DecidedBy, tuple[Escalation, ...], str | None]:
        """Strict mode: judge first (if enabled); unsure, erroring or off -> a human (`ask`)."""
        human = Escalation(to="human", result="requested")
        judge = self.judge if policy.judge.enabled else None
        if judge is None:
            return Outcome.ASK, DecidedBy.POLICY_DEFAULT, (human,), None
        why = self._reason(Outcome.ASK, reason_codes, None, req.tool_name)
        t = time.perf_counter()
        verdict: JudgeVerdict | None = await judge.judge(to_state_text(dossier), why)
        ms = (time.perf_counter() - t) * 1000
        judge_out.update(verdict=verdict, model_id=getattr(judge, "model_id", "judge"), ms=ms)
        if verdict is None:
            reason_codes.append("judge_unsure")
            return (
                Outcome.ASK,
                DecidedBy.POLICY_DEFAULT,
                (Escalation(to="judge", result="error", latency_ms=ms), human),
                None,
            )
        judged = Escalation(to="judge", result=verdict.decision, latency_ms=ms)
        reason = f"{req.tool_name}: judge: {verdict.reason}"
        if verdict.decision == "allow":
            return Outcome.ALLOW, DecidedBy.JUDGE, (judged,), reason
        if verdict.decision == "deny":
            return Outcome.BLOCK, DecidedBy.JUDGE, (judged,), reason
        reason_codes.append("judge_unsure")
        return Outcome.ASK, DecidedBy.JUDGE, (judged, human), reason

    @staticmethod
    def _reason(outcome: Outcome, codes: Sequence[str], risk: RiskClass | None, tool: str) -> str:
        parts = []
        for c in dict.fromkeys(codes):
            if c in REASON_TEXT:
                parts.append(REASON_TEXT[c])
            elif c.startswith("policy_ask_"):
                parts.append(
                    f"policy asks before {c.removeprefix('policy_ask_').replace('_', ' ')} actions"
                )
        if outcome is Outcome.ALLOW:
            return f"{tool}: allowed" + (f" ({'; '.join(parts)})" if parts else "")
        # The adapter adds the verb ("TaintTrap blocked:", "TaintTrap · Task: …").
        return f"{tool}: " + ("; ".join(parts) if parts else "policy")

    def _run_shadow(self, dossier: Any, log_entry: dict[str, Any]) -> None:
        async def run() -> None:
            assert self.shadow is not None
            try:
                a = await self.shadow.assess(dossier)
                log_entry["shadow"] = {
                    "model_version": a.model_id,
                    "assessment": _assessment_json(a),
                }
            except Exception:  # noqa: BLE001,S110 - shadow failures are never fatal
                pass

        task = asyncio.ensure_future(run())
        self._shadow_tasks.add(task)
        task.add_done_callback(self._shadow_tasks.discard)


def _rule_json(r: RuleResult) -> dict[str, Any]:
    return {
        "rule_id": r.rule_id,
        "verdict": r.verdict,
        "final": r.final,
        "severity": r.severity,
        "evidence": mask_text(r.evidence),
    }


def _assessment_json(a: Assessment) -> dict[str, Any]:
    return {
        "aligned": round(a.aligned, 4),
        "risk": a.risk.value,
        "risk_probs": {k.value: round(v, 4) for k, v in a.risk_probs.items()},
        "sensitive_data": round(a.sensitive_data, 4),
        "needs_human": round(a.needs_human, 4),
        "model_id": a.model_id,
        "latency_ms": round(a.latency_ms, 2),
        "rationale": a.rationale,
    }


def now_iso() -> str:
    return utcnow().isoformat()


def _shell_arg(arguments: dict[str, Any]) -> str | None:
    return next((v for k in SHELL_ARGS if isinstance(v := arguments.get(k), str)), None)


def _addressee_path(path: str) -> bool:
    parts = [p for p in path.split(".")[1:] if not p.isdigit()]
    return bool(parts) and parts[-1].lower() in ADDRESSEE_KEYS
