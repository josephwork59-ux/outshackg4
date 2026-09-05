"""Log parsing / normalization. Deterministic, no LLM involved."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class LogEvent:
    line_no: int
    raw: str
    source: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    path: Optional[str] = None
    extra: dict = field(default_factory=dict)


_AUTH_FAIL_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for"
    r"(?: invalid user)? (?P<user>\S+) from (?P<ip>[\d.]+)"
)
_AUTH_OK_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Accepted password for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
_NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+) - \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+"'
    r' (?P<status>\d{3}) \d+'
)


def tail_logs(source: str, since: int | None = None) -> list[str]:
    """Pull recent entries from a log file. `since` = number of lines to skip
    from the top (kept simple for the demo — a real deployment would use file
    offsets / a proper log-shipping agent)."""
    p = Path(source)
    if not p.exists():
        return []
    lines = p.read_text(errors="replace").splitlines()
    if since:
        lines = lines[since:]
    return lines


def parse_log(line: str, fmt: str, line_no: int = 0, source: str = "") -> LogEvent:
    """Normalize one raw line into a common LogEvent, based on `fmt`
    ('auth', 'nginx', 'json', 'auto')."""
    if fmt == "auto":
        fmt = _sniff_format(line)

    if fmt == "auth":
        m = _AUTH_FAIL_RE.search(line) or _AUTH_OK_RE.search(line)
        if m:
            gd = m.groupdict()
            return LogEvent(
                line_no=line_no, raw=line, source=source,
                source_ip=gd.get("ip"), user=gd.get("user"),
                action="ssh_login",
                status="failed" if "Failed" in line else "success",
            )
        return LogEvent(line_no=line_no, raw=line, source=source, action="unknown")

    if fmt == "nginx":
        m = _NGINX_RE.search(line)
        if m:
            gd = m.groupdict()
            return LogEvent(
                line_no=line_no, raw=line, source=source,
                source_ip=gd.get("ip"), action=gd.get("method"),
                path=gd.get("path"), status=gd.get("status"),
            )
        return LogEvent(line_no=line_no, raw=line, source=source, action="unknown")

    if fmt == "json":
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return LogEvent(line_no=line_no, raw=line, source=source, action="unparseable")
        return LogEvent(
            line_no=line_no, raw=line, source=source,
            source_ip=obj.get("source_ip") or obj.get("ip"),
            user=obj.get("user"),
            action=obj.get("action") or obj.get("event"),
            status=str(obj.get("status", "")),
            extra=obj,
        )

    return LogEvent(line_no=line_no, raw=line, source=source, action="unrecognized_format")


def _sniff_format(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return "json"
    if _NGINX_RE.search(line):
        return "nginx"
    if "sshd" in line or "Failed password" in line or "Accepted password" in line:
        return "auth"
    return "json"


def parse_all(source: str, fmt: str = "auto") -> list[LogEvent]:
    return [
        parse_log(line, fmt, line_no=i, source=source)
        for i, line in enumerate(tail_logs(source))
        if line.strip()
    ]
