from tainttrap.core.dossier import UNKNOWN_TASK, build_dossier, to_state_text
from tainttrap.core.types import ArgumentProvenance, Origin, RiskClass


def make(**kw):
    base = dict(
        task="Email the report to Ana",
        tool="send_email",
        registry_entry=None,
        risk_class=RiskClass.EXTERNAL_COMMUNICATION,
        arguments={"to": "ana@x.example", "body": "hi"},
        provenance=[],
        recent_actions=[],
    )
    base.update(kw)
    return build_dossier(**base)


def test_secret_placeholders(secrets_fixture):
    d = make(arguments={"body": "key " + secrets_fixture["secrets"]["aws_access_key"]})
    assert "<SECRET:aws-access-token>" in d.args["body"]
    assert secrets_fixture["secrets"]["aws_access_key"] not in to_state_text(d)


def test_truncation_keeps_start_and_end():
    body = "START-" + "x" * 20000 + "-END"
    d = make(arguments={"body": body}, tier="cpu-int8")
    assert d.truncated
    assert d.args["body"].startswith("START-") and d.args["body"].endswith("-END")
    assert "…[truncated" in d.args["body"]
    assert d.token_estimate <= 512


def test_gpu_budget():
    d = make(arguments={"body": "y" * 20000}, tier="gpu-fp16")
    assert d.token_estimate <= 2048


def test_recent_actions_limit_and_unknown_task():
    d = make(task=None, recent_actions=[f"t{i}" for i in range(12)])
    assert d.recent_actions == tuple(f"t{i}" for i in range(4, 12))
    assert d.user_task == UNKNOWN_TASK


def test_provenance_lists():
    d = make(
        provenance=[
            ArgumentProvenance(path="args.to", origin=Origin.UNTRUSTED),
            ArgumentProvenance(path="args.body", origin=Origin.USER),
        ]
    )
    assert d.untrusted_fields == ("args.to",) and d.user_fields == ("args.body",)


def test_long_task_truncated():
    d = make(task="t" * 5000)
    assert d.truncated and len(d.user_task) < 5000
