"""Secret placeholders for dossiers and masks for logs (FR-027, NFR-5, FR-033)."""

from __future__ import annotations

import re
from typing import Any

from tainttrap.core.rules.secrets import SecretFinding, scan_value

_DROP_KEYS = re.compile(r"(?i)^(env|authorization|api[_-]?key|password|token|secret)$")
_DROPPED = "***redacted***"


def _replace(text: str, findings: list[SecretFinding], fmt: str) -> str:
    out, last = [], 0
    for f in findings:
        if f.type == "sensitive_path":
            continue  # a path is not itself secret; keep it readable
        out.append(text[last : f.start])
        out.append(fmt.format(type=f.type))
        last = f.end
    out.append(text[last:])
    return "".join(out)


def placeholder_text(text: str) -> str:
    """Dossier form: each secret becomes `<SECRET:type>`."""
    return _replace(text, scan_value(text), "<SECRET:{type}>")


def mask_text(text: str) -> str:
    """Log/reason form: each secret becomes `***type***`."""
    return _replace(text, scan_value(text), "***{type}***")


def placeholder_json(obj: Any) -> Any:
    return _walk(obj, placeholder_text)


def mask_json(obj: Any) -> Any:
    return _walk(obj, mask_text)


def _walk(obj: Any, fn: Any) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {
            k: (_DROPPED if isinstance(k, str) and _DROP_KEYS.match(k) else _walk(v, fn))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_walk(v, fn) for v in obj]
    return obj
