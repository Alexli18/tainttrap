import pytest

from tainttrap.core.policy import PolicyError, load_policy, parse_policy, validate_file
from tainttrap.core.types import FailureMode, Mode


def test_defaults():
    p = load_policy()
    assert p.mode is Mode.OBSERVE
    assert p.failure_mode is FailureMode.FAIL_OPEN
    assert p.judge.enabled is False
    assert p.human.timeout_s == 60
    assert p.risk_actions["financial"].aligned_mid == "block"


@pytest.mark.parametrize(
    "data, field",
    [
        ({"thresholds": {"aligned_block": 0.9, "aligned_allow": 0.5}}, "thresholds"),
        ({"bogus": 1}, "bogus"),
        ({"telemetry": True}, "telemetry"),
        ({"judge": {"enabled": True}}, "judge"),
        (
            {
                "judge": {
                    "enabled": True,
                    "provider": "anthropic",
                    "endpoint": "https://api.anthropic.com",
                    "model": "claude-haiku-5-5",
                }
            },
            "judge",
        ),
        ({"rules": {"commands": {"deny": ["(unclosed"]}}}, "rules.commands.deny"),
    ],
)
def test_invalid_policies_name_the_field(data, field):
    with pytest.raises(PolicyError) as e:
        parse_policy(data)
    assert any(p.startswith(field) for p in e.value.problems), e.value.problems


def test_remote_judge_needs_opt_in():
    p = parse_policy(
        {
            "judge": {
                "enabled": True,
                "provider": "anthropic",
                "endpoint": "https://api.anthropic.com",
                "model": "claude-haiku-5-5",
                "allow_remote": True,
            }
        }
    )
    assert p.judge.allow_remote
    local = parse_policy(
        {
            "judge": {
                "enabled": True,
                "provider": "openai_compatible",
                "endpoint": "http://127.0.0.1:11434/v1",
                "model": "qwen3:4b",
            }
        }
    )
    assert local.judge.enabled


def test_validate_file(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\nmode: loud\n")
    assert any(p.startswith("mode") for p in validate_file(f))
    f.write_text("version: 1\nmode: soft\n")
    assert validate_file(f) == []
