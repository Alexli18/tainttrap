"""OpenAI-compatible chat completions judge: OpenAI, Ollama, llama.cpp, vLLM, LM Studio (T079)."""

from __future__ import annotations

from typing import Any

from tainttrap.core.judge.base import JUDGE_SCHEMA, SYSTEM_PROMPT, HttpJudge


class OpenAICompatJudge(HttpJudge):
    def request(self, user: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        endpoint = (self.settings.endpoint or "").rstrip("/")
        payload = {
            "model": self.settings.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "tainttrap_verdict",
                    "strict": True,
                    "schema": JUDGE_SCHEMA,
                },
            },
        }
        key = self._api_key()
        return (
            f"{endpoint}/chat/completions",
            payload,
            ({"Authorization": f"Bearer {key}"} if key else {}),
        )

    def extract(self, body: dict[str, Any]) -> str:
        return str(body["choices"][0]["message"]["content"])
