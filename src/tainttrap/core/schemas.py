"""Packaged JSON schemas (copies of specs/001-tainttrap-mvp/contracts/*.schema.json)."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

SCHEMAS = ("policy", "dossier", "training-record", "log-entry")


@cache
def load_schema(name: str) -> dict[str, Any]:
    text = resources.files("tainttrap.data.schemas").joinpath(f"{name}.schema.json").read_text()
    data: dict[str, Any] = json.loads(text)
    return data
