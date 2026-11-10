"""Anthropic Messages API judge with structured output (T080). Example model: claude-haiku-5-5."""

from __future__ import annotations

from typing import Any

from tainttrap.core.judge.base import JUDGE_SCHEMA, SYSTEM_PROMPT, HttpJudge

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicJudge(HttpJudge):
    def request(self, user: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        endpoint = (self.settings.endpoint or "https://api.anthropic.com").rstrip("/")
        payload = {
            "model": self.settings.model,
            "max_tokens": 300,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": JUDGE_SCHEMA}},
        }
        headers = {"anthropic-version": ANTHROPIC_VERSION}
        key = self._api_key()
        if key:
            headers["x-api-key"] = key
        return f"{endpoint}/v1/messages", payload, headers

    def extract(self, body: dict[str, Any]) -> str:
        return "".join(b.get("text", "") for b in body["content"] if b.get("type") == "text")
