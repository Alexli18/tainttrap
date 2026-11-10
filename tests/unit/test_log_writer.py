import json
from datetime import UTC, datetime, timedelta

import jsonschema

from tainttrap.core.schemas import load_schema
from tainttrap.logstore.writer import LogWriter, log_file_for, read_entries


def test_masks_and_validates(tmp_path, secrets_fixture):
    w = LogWriter(tmp_path, synchronous=True)
    key = secrets_fixture["secrets"]["github_pat"]
    w.write(
        {
            "kind": "decision",
            "session_id": "s",
            "mode": "soft",
            "policy_hash": "h",
            "decision": {
                "outcome": "block",
                "enforced": True,
                "effective_outcome": "block",
                "decided_by": "rules",
                "reason": f"blocked {key}",
            },
            "rule_results": [{"rule_id": "x", "verdict": "block", "final": True, "evidence": key}],
            "detail": json.dumps({"args": {"token": key}}),
        }
    )
    files = list(tmp_path.glob("decisions-*.jsonl"))
    assert [f.name for f in files] == [log_file_for(datetime.now(UTC), tmp_path).name]
    text = files[0].read_text()
    assert key not in text
    entry = json.loads(text.splitlines()[0])
    jsonschema.validate(entry, load_schema("log-entry"))


def test_retention(tmp_path):
    old = tmp_path / f"decisions-{(datetime.now(UTC) - timedelta(days=100)):%Y-%m-%d}.jsonl"
    old.write_text("{}\n")
    LogWriter(tmp_path, retain_days=90, synchronous=True)
    assert not old.exists()


def test_async_writer_flush(tmp_path):
    w = LogWriter(tmp_path)
    for i in range(20):
        w.write({"kind": "heartbeat", "n": i})
    w.flush()
    w.close()
    assert len(read_entries(tmp_path)) == 20
