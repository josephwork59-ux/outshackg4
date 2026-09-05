"""Pluggable LLM client.

Reasoning agents (Threat Intel summaries, Incident Response plans, Policy
Checker rationale, the executive summary) call `LLMClient.complete(...)`.

If `OPENAI_API_KEY` is set, this wraps the real OpenAI API. If it is not set
(e.g. a fresh clone with no keys configured), it falls back to a deterministic
MockLLM so `make demo` still runs end to end with zero setup — the output is
canned-but-realistic text rather than a live model response. Swapping in a
real key later upgrades every agent's output automatically, no code changes.

The LLM is only ever used to *explain, correlate, prioritize, and write
plans* — see guardrail in the top-level README: it never invents findings,
CVEs, or scanner output. All facts fed to it come from deterministic
tools/scanners upstream.
"""
from __future__ import annotations

import os
import textwrap
from abc import ABC, abstractmethod


class LLMBackend(ABC):
    name: str

    @abstractmethod
    def complete(self, system: str, prompt: str, *, max_tokens: int = 500) -> str:
        ...


class MockLLM(LLMBackend):
    """Deterministic, template-based fallback. No network calls, no API key.

    It does not "make things up" about severity or facts — callers pass the
    already-computed facts into the prompt, and this backend just reflects a
    plausible-sounding writeup of them so downstream code and the demo have
    real text to render.
    """

    name = "mock"

    def complete(self, system: str, prompt: str, *, max_tokens: int = 500) -> str:
        summary_line = prompt.strip().splitlines()[0] if prompt.strip() else ""
        body = textwrap.dedent(
            f"""\
            [mock-llm output — set OPENAI_API_KEY to use a real model]
            Context: {summary_line}

            Based on the structured facts provided, this appears to be a
            legitimate finding requiring analyst review. Recommended next
            step: validate the evidence cited, confirm scope/impact against
            the affected asset's criticality, and follow the recommended fix
            or the phased incident plan attached to this finding.
            """
        )
        return body[:max_tokens]


class OpenAILLM(LLMBackend):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI  # imported lazily so mock mode has no dep

        self._client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._model = model

    def complete(self, system: str, prompt: str, *, max_tokens: int = 500) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""


class LLMClient:
    """Facade agents call. Picks a backend once, at construction time."""

    def __init__(self, backend: LLMBackend | None = None):
        if backend is not None:
            self.backend = backend
        elif os.environ.get("OPENAI_API_KEY"):
            try:
                self.backend = OpenAILLM(model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
            except Exception:
                # Never let a bad key / missing SDK crash a security scan.
                self.backend = MockLLM()
        else:
            self.backend = MockLLM()

    def complete(self, system: str, prompt: str, *, max_tokens: int = 500) -> str:
        try:
            return self.backend.complete(system, prompt, max_tokens=max_tokens)
        except Exception as exc:  # fail safe — never crash an agent on LLM error
            return f"[llm-error: {exc}] falling back to facts only."


_default_client: LLMClient | None = None


def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client
