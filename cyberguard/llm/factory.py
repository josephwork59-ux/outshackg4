"""Pick an LLM backend from the environment.

CYBERGUARD_LLM = deterministic (default) | claude

`claude` requires the `anthropic` package and ANTHROPIC_API_KEY; if either is
missing we log a note and fall back to deterministic so a run never breaks on
LLM availability.
"""

from __future__ import annotations

import os

from .deterministic import DeterministicLLM


def get_llm(prefer: str | None = None):
    choice = (prefer or os.environ.get("CYBERGUARD_LLM") or "deterministic").lower()
    if choice in ("claude", "claude-sonnet-5", "anthropic"):
        try:
            from .claude import ClaudeLLM

            return ClaudeLLM()
        except Exception as exc:  # noqa: BLE001 - any failure -> safe fallback
            print(f"[llm] claude backend unavailable ({exc}); using deterministic")
    return DeterministicLLM()
