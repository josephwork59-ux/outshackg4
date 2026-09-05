"""Tiny, dependency-free version comparison good enough for advisory ranges.

Handles dotted numeric releases with an optional trailing pre-release tag
(e.g. 5.4, 2.10.1, 1.0rc1). Not a full PEP 440 implementation - it errs on the
side of flagging ("uncertain" is reported by the caller, not silently ignored).
"""

from __future__ import annotations

import re

_NUM = re.compile(r"(\d+)")


def _key(version: str) -> tuple:
    version = version.strip().lstrip("vV=<>~!^ ")
    main = re.split(r"[-+ ]", version, maxsplit=1)[0]
    parts = main.split(".")
    key: list[int] = []
    for p in parts:
        m = _NUM.match(p)
        key.append(int(m.group(1)) if m else 0)
    # pre-release (rc/a/b/dev) sorts before the plain release
    pre = 0 if re.search(r"(?i)(rc|a|b|alpha|beta|dev|pre)", version) else 1
    key.append(pre)
    return tuple(key)


def _cmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    ka += (0,) * (n - len(ka))
    kb += (0,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def satisfies(version: str, spec: str) -> bool:
    """True if `version` matches a comma-separated spec such as ">=1.0,<1.2" or "<5.4"."""
    version = (version or "").strip()
    if not version:
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"(<=|>=|==|<|>|!=)?\s*(.+)", clause)
        if not m:
            return False
        op, ref = m.group(1) or "==", m.group(2).strip()
        c = _cmp(version, ref)
        ok = {
            "<": c < 0,
            "<=": c <= 0,
            ">": c > 0,
            ">=": c >= 0,
            "==": c == 0,
            "!=": c != 0,
        }[op]
        if not ok:
            return False
    return True
