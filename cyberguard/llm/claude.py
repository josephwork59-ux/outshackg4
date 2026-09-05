"""Optional `claude-sonnet-5` backend for the LLM layer.

Enabled only when the `anthropic` package is installed and ANTHROPIC_API_KEY is
set (see llm/factory.py). Falls back to DeterministicLLM otherwise so the
pipeline always runs.

Callers pass already-redacted text; do not add anything here that would forward
secrets or raw PII to the API.
"""

from __future__ import annotations

import json
import os

MODEL = "claude-sonnet-5"


class ClaudeLLM:
    name = "claude-sonnet-5"

    def __init__(self, model: str = MODEL) -> None:
        import anthropic  # imported lazily; optional dependency

        self.model = model
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    def _ask(self, system: str, user: str, max_tokens: int = 400) -> str:
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in msg.content if getattr(block, "type", "") == "text").strip()

    def summarize_advisory(self, text: str) -> str:
        return self._ask(
            "You are a security analyst. Summarize the advisory in one short paragraph: "
            "affected versions, attack vector, patch availability, exploit maturity. "
            "State only what the text supports.",
            text[:6000],
        )

    def correlation_narrative(self, bullet_points: list[str]) -> str:
        return self._ask(
            "You are a SOC analyst. Given these correlated findings, write 2-3 sentences "
            "describing the likely activity chain. Do not speculate beyond the evidence.",
            "\n".join(f"- {b}" for b in bullet_points),
        )

    def executive_summary(self, facts: dict) -> str:
        return self._ask(
            "You are a security lead writing for executives. <=200 words, plain language, "
            "no jargon dumps. Make clear nothing was auto-remediated.",
            json.dumps(facts, indent=2),
        )

    def incident_comms(self, facts: dict) -> str:
        return self._ask(
            "You are an incident commander. Draft a short internal notification. "
            "Mark it DRAFT and note approval is required before action.",
            json.dumps(facts, indent=2),
        )
