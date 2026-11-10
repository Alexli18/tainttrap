"""Golden set (test level 2, SC-008): hand-written scenarios with expected decisions."""

import asyncio
from pathlib import Path

import pytest
import yaml

from tainttrap.core.engine import CheckRequest, Engine, SessionView
from tainttrap.core.model.base import StubProvider
from tainttrap.core.policy import parse_policy
from tainttrap.core.provenance import ProvenanceIndex
from tainttrap.core.registry import Registry
from tainttrap.core.rules import default_rules
from tainttrap.core.types import Adapter, Assessment, RiskClass

SCENARIOS = sorted((Path(__file__).parent / "scenarios").glob("*.yaml"))


@pytest.mark.parametrize("path", SCENARIOS, ids=[p.stem for p in SCENARIOS])
def test_golden(path):
    sc = yaml.safe_load(path.read_text())
    prov = ProvenanceIndex()
    for i, obs in enumerate(sc.get("prior_observations", [])):
        prov.observe("s", f"obs{i}", [obs["response"]])
    a = sc["stub_assessment"]
    risk = RiskClass(a["risk"])
    stub = StubProvider(
        Assessment(
            aligned=a["aligned"],
            risk=risk,
            risk_probs={risk: 1.0},
            sensitive_data=a["sensitive_data"],
            needs_human=a["needs_human"],
        )
    )
    engine = Engine(Registry(), prov, stub, default_rules())
    call = sc["call"]
    req = CheckRequest(
        adapter=Adapter.SDK,
        session_id="s",
        call_id="c",
        tool_name=call["tool_name"],
        arguments=call["arguments"],
        server=call.get("server"),
        cwd="/repo",
    )
    view = SessionView(task=sc.get("task"), scope_ids=("s",))
    result = asyncio.run(engine.decide(req, view, parse_policy(sc.get("policy_overrides", {}))))
    d, exp = result.decision, sc["expected"]
    assert d.outcome.value == exp["outcome"], (d.reason, d.reason_codes)
    if "decided_by" in exp:
        assert d.decided_by.value == exp["decided_by"]
    if "decided_by_not" in exp:
        assert d.decided_by.value != exp["decided_by_not"]
    for code in exp.get("reason_codes_include", []):
        assert code in d.reason_codes, d.reason_codes
    if "risk_class" in exp:
        assert result.log_entry["dossier"]["tool_risk_class"] == exp["risk_class"]
