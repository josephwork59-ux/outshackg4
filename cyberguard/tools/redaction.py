"""Secret / PII redaction.

Guardrail: no raw credential or PII ever reaches an evidence snippet, a log
line, or the LLM. IP addresses are deliberately kept - they are needed as
evidence and for correlation.
"""

from __future__ import annotations

import re

# (name, compiled pattern, replacement). Order matters - most specific first.
_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "private_key_block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED:private-key]",
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws-akid]"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        "[REDACTED:jwt]",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        "[REDACTED:slack-token]",
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b"),
        "[REDACTED:github-token]",
    ),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|passwd|password|access[_-]?key|auth)\b"
            r"(\s*[:=]\s*)"
            r"([\"']?)([A-Za-z0-9/+=_\-\.]{6,})\3"
        ),
        r"\1\2\3[REDACTED:secret]\3",
    ),
    (
        "basic_auth_url",
        re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
        "://[REDACTED:userinfo]@",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED:email]",
    ),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for _name, pattern, repl in _RULES:
        out = pattern.sub(repl, out)
    return out


def redact_lines(lines: list[str]) -> list[str]:
    return [redact(line) for line in lines]


def looks_like_secret(text: str) -> str | None:
    """Return the rule name if `text` appears to contain a secret, else None.

    Used by the vulnerability scanner's built-in secret check.
    """
    for name, pattern, _repl in _RULES:
        if name in ("email", "basic_auth_url"):
            continue
        if pattern.search(text):
            return name
    return None
