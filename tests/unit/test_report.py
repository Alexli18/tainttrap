from tainttrap.logstore.report import build_report


def entry(outcome, enforced=True, decided_by="model", risk="read_only", tool="Read", codes=()):
    return {
        "kind": "decision",
        "entry_id": f"e-{outcome}-{tool}",
        "call": {"tool_name": tool},
        "dossier": {"tool_risk_class": risk},
        "decision": {
            "outcome": outcome,
            "enforced": enforced,
            "decided_by": decided_by,
            "reason_codes": list(codes),
        },
    }


def test_counts_match_log():
    es = [
        entry("allow"),
        entry("allow"),
        entry("block", tool="Bash", risk="external_communication"),
        entry("ask", risk="destructive"),
        entry("allow", decided_by="failure_mode"),
        {"kind": "heartbeat"},
    ]
    r = build_report(es, by="risk")
    assert (r.checked, r.allowed, r.blocked, r.asked, r.failure_mode) == (5, 3, 1, 1, 1)
    assert r.by["external_communication"]["block"] == 1
    assert r.would_be is False


def test_observe_is_would_be():
    r = build_report([entry("block", enforced=False), entry("allow", enforced=False)])
    assert r.would_be and r.blocked == 1


def test_flags_counted():
    e = entry("block")
    assert build_report([e], flagged_ids={e["entry_id"]}).flagged == 1
