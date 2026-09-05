"""Secret/PII redaction — used by every agent before evidence ever reaches
storage, a report, or the LLM. Guardrail: "never send secrets to the LLM."
"""
from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)(\s*[:=]\s*)([^\s'\"]+)"),
     r"\1\2[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9\-_.]+\b"), "Bearer [REDACTED]"),
]


def redact(text: str) -> str:
    """Best-effort redaction of secrets/PII in a log line or code snippet
    before it is stored as Finding evidence or shown to an LLM. Not a
    substitute for not logging secrets in the first place — defense in depth."""
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_lines(lines: list[str]) -> list[str]:
    return [redact(line) for line in lines]
