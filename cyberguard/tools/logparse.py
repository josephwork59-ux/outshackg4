"""Normalize heterogeneous log lines into a common Event schema."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, Optional

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

# Common / combined nginx-apache access log.
_NGINX = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


@dataclass
class Event:
    raw: str
    source: str
    ts: Optional[str] = None
    source_ip: Optional[str] = None
    process: Optional[str] = None
    kind: str = "generic"  # auth_fail | auth_ok | http | generic
    message: str = ""
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    fields: dict = field(default_factory=dict)


_AUTH_FAIL = re.compile(
    r"(?i)(failed password|authentication failure|invalid user|failed publickey"
    r"|not in sudoers|incorrect password attempts|maximum authentication attempts)"
)
_AUTH_OK = re.compile(r"(?i)(accepted password|accepted publickey|session opened for user)")


def _classify_syslog(msg: str) -> str:
    if _AUTH_FAIL.search(msg):
        return "auth_fail"
    if _AUTH_OK.search(msg):
        return "auth_ok"
    return "generic"


def parse_line(line: str, source: str, fmt: str = "auto") -> Optional[Event]:
    line = line.rstrip("\n")
    if not line.strip():
        return None

    if fmt in ("auto", "nginx", "apache"):
        m = _NGINX.match(line)
        if m:
            ip = m.group("ip")
            return Event(
                raw=line,
                source=source,
                ts=m.group("ts"),
                source_ip=ip if _IPV4.fullmatch(ip) else None,
                kind="http",
                message=f'{m.group("method")} {m.group("path")} -> {m.group("status")}',
                http_method=m.group("method"),
                http_path=m.group("path"),
                http_status=int(m.group("status")),
                fields={"ua": m.group("ua") or "", "referer": m.group("referer") or ""},
            )

    if fmt in ("auto", "syslog"):
        m = _SYSLOG.match(line)
        if m:
            msg = m.group("msg")
            ipm = _IPV4.search(msg)
            return Event(
                raw=line,
                source=source,
                ts=m.group("ts"),
                source_ip=ipm.group(0) if ipm else None,
                process=m.group("proc"),
                kind=_classify_syslog(msg),
                message=msg,
            )

    ipm = _IPV4.search(line)
    return Event(
        raw=line,
        source=source,
        source_ip=ipm.group(0) if ipm else None,
        kind="generic",
        message=line,
    )


def iter_events(path: str, fmt: str = "auto") -> Iterator[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line, source=path, fmt=fmt)
            if ev is not None:
                yield ev
