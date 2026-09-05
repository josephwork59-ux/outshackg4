"""LLM client protocol.

Any implementation must be safe to call with untrusted text: callers pass
already-redacted content, and implementations must never be given secrets.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMClient(Protocol):
    name: str

    def summarize_advisory(self, text: str) -> str:
        """One-paragraph plain-language summary of a vulnerability advisory."""

    def correlation_narrative(self, bullet_points: list[str]) -> str:
        """Short narrative tying correlated findings together."""

    def executive_summary(self, facts: dict) -> str:
        """<=200 word executive summary of a scan, from structured facts."""

    def incident_comms(self, facts: dict) -> str:
        """Internal notification draft for an incident."""
