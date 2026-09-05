"""Deterministic detection rules + a light statistical baseline. This is the
"determinism where possible" half of the Log Monitor agent — the LLM never
invents these detections, it only explains clusters these rules surface.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass

from .parsers import LogEvent

SQLI_PATTERNS = re.compile(r"(?i)(\bunion\s+select\b|\bor\s+1=1\b|--\s|;--|/\*.*\*/|'\s*or\s*')")
XSS_PATTERNS = re.compile(r"(?i)(<script|onerror=|onload=|javascript:)")
PRIV_ESC_KEYWORDS = re.compile(r"(?i)(sudo:.*COMMAND=.*/(passwd|visudo|usermod)|added to group root|setuid)")
LOG_TAMPER_KEYWORDS = re.compile(r"(?i)(auditd.*stopped|rsyslogd.*exiting|log.*(cleared|truncated|deleted)|history -c)")

BRUTE_FORCE_THRESHOLD = 5      # failed logins from same IP within window
PORT_SCAN_THRESHOLD = 8        # distinct dest ports/paths from same IP
EXFIL_BYTES_THRESHOLD = 50_000_000  # 50MB single-response anomaly (demo-scaled)
BEACON_JITTER_TOLERANCE = 2.0  # seconds stddev allowed to call it "periodic"


@dataclass
class DetectionResult:
    signature: str
    attack_technique: str  # MITRE ATT&CK id
    title: str
    description: str
    severity: str
    confidence: float
    evidence_lines: list[str]
    source_ips: list[str]


def detect_brute_force(events: list[LogEvent]) -> list[DetectionResult]:
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.action == "ssh_login" and e.status == "failed" and e.source_ip:
            by_ip[e.source_ip].append(e)

    results = []
    for ip, evs in by_ip.items():
        if len(evs) >= BRUTE_FORCE_THRESHOLD:
            users = sorted({e.user for e in evs if e.user})
            confidence = min(0.5 + 0.05 * len(evs), 0.98)
            results.append(DetectionResult(
                signature=f"brute_force:{ip}",
                attack_technique="T1110",  # Brute Force
                title=f"SSH brute-force / credential-stuffing from {ip}",
                description=(
                    f"{len(evs)} failed SSH logins from {ip} against "
                    f"{len(users)} distinct username(s) ({', '.join(users[:5])}"
                    f"{'...' if len(users) > 5 else ''}) — consistent with a "
                    f"brute-force or credential-stuffing attack."
                ),
                severity="high" if len(evs) >= 10 else "medium",
                confidence=confidence,
                evidence_lines=[e.raw for e in evs[:10]],
                source_ips=[ip],
            ))
    return results


def detect_port_scan(events: list[LogEvent]) -> list[DetectionResult]:
    by_ip: dict[str, set] = defaultdict(set)
    lines_by_ip: dict[str, list[str]] = defaultdict(list)
    for e in events:
        if e.source_ip and e.path:
            by_ip[e.source_ip].add(e.path)
            lines_by_ip[e.source_ip].append(e.raw)

    results = []
    for ip, paths in by_ip.items():
        if len(paths) >= PORT_SCAN_THRESHOLD:
            results.append(DetectionResult(
                signature=f"scan:{ip}",
                attack_technique="T1595",  # Active Scanning
                title=f"Reconnaissance / path scan from {ip}",
                description=(
                    f"{ip} requested {len(paths)} distinct paths in a short "
                    f"window — consistent with automated reconnaissance."
                ),
                severity="medium",
                confidence=0.6,
                evidence_lines=lines_by_ip[ip][:10],
                source_ips=[ip],
            ))
    return results


def detect_injection_probes(events: list[LogEvent]) -> list[DetectionResult]:
    results = []
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.path and (SQLI_PATTERNS.search(e.path) or XSS_PATTERNS.search(e.path)):
            by_ip[e.source_ip or "unknown"].append(e)

    for ip, evs in by_ip.items():
        kind = "SQLi" if any(SQLI_PATTERNS.search(e.path or "") for e in evs) else "XSS"
        results.append(DetectionResult(
            signature=f"injection:{kind}:{ip}",
            attack_technique="T1190",  # Exploit Public-Facing Application
            title=f"{kind} injection probe from {ip}",
            description=f"{len(evs)} request(s) from {ip} contain {kind}-style payloads in the URL/path.",
            severity="high",
            confidence=0.75,
            evidence_lines=[e.raw for e in evs[:10]],
            source_ips=[ip],
        ))
    return results


def detect_privilege_escalation(events: list[LogEvent]) -> list[DetectionResult]:
    hits = [e for e in events if PRIV_ESC_KEYWORDS.search(e.raw)]
    if not hits:
        return []
    return [DetectionResult(
        signature="priv_esc",
        attack_technique="T1548",  # Abuse Elevation Control Mechanism
        title="Possible privilege escalation activity",
        description=f"{len(hits)} log line(s) indicate elevation-related commands (sudo/usermod/setuid).",
        severity="critical",
        confidence=0.65,
        evidence_lines=[e.raw for e in hits[:10]],
        source_ips=[e.source_ip for e in hits if e.source_ip],
    )]


def detect_log_tampering(events: list[LogEvent]) -> list[DetectionResult]:
    hits = [e for e in events if LOG_TAMPER_KEYWORDS.search(e.raw)]
    if not hits:
        return []
    return [DetectionResult(
        signature="log_tampering",
        attack_technique="T1070",  # Indicator Removal
        title="Possible log tampering / disabled logging",
        description=f"{len(hits)} log line(s) indicate logging services were stopped or history cleared.",
        severity="critical",
        confidence=0.7,
        evidence_lines=[e.raw for e in hits[:10]],
        source_ips=[],
    )]


def detect_exfil_volume(events: list[LogEvent]) -> list[DetectionResult]:
    """Look for JSON app-log events carrying a `bytes_out` field far above baseline."""
    sizes = [e.extra.get("bytes_out") for e in events if isinstance(e.extra.get("bytes_out"), (int, float))]
    results = []
    if len(sizes) >= 3:
        mean = statistics.mean(sizes)
        for e in events:
            b = e.extra.get("bytes_out")
            if isinstance(b, (int, float)) and (b > EXFIL_BYTES_THRESHOLD or b > mean * 10):
                results.append(DetectionResult(
                    signature=f"exfil:{e.source_ip}:{e.line_no}",
                    attack_technique="T1041",  # Exfiltration Over C2 Channel
                    title=f"Data-exfiltration volume anomaly ({b} bytes)",
                    description=(
                        f"Response/transfer of {b} bytes is far above the observed "
                        f"baseline mean of {mean:.0f} bytes — possible data exfiltration."
                    ),
                    severity="high",
                    confidence=0.55,
                    evidence_lines=[e.raw],
                    source_ips=[e.source_ip] if e.source_ip else [],
                ))
    return results


def detect_c2_beaconing(events: list[LogEvent]) -> list[DetectionResult]:
    """Flag destination IPs contacted at suspiciously regular intervals —
    classic C2 beacon behavior. Uses JSON events with an epoch `ts` field."""
    by_dst: dict[str, list[float]] = defaultdict(list)
    for e in events:
        dst = e.extra.get("dest_ip")
        ts = e.extra.get("ts")
        if dst and isinstance(ts, (int, float)):
            by_dst[dst].append(ts)

    results = []
    for dst, times in by_dst.items():
        if len(times) < 5:
            continue
        times.sort()
        deltas = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        if len(deltas) >= 4 and statistics.pstdev(deltas) <= BEACON_JITTER_TOLERANCE:
            results.append(DetectionResult(
                signature=f"c2_beacon:{dst}",
                attack_technique="T1071",  # Application Layer Protocol (C2)
                title=f"Periodic beacon-like traffic to {dst}",
                description=(
                    f"{len(times)} connections to {dst} at near-constant intervals "
                    f"(avg {statistics.mean(deltas):.1f}s, stddev {statistics.pstdev(deltas):.2f}s) "
                    f"— consistent with C2 beaconing."
                ),
                severity="high",
                confidence=0.6,
                evidence_lines=[f"beacon to {dst} at t={t}" for t in times[:10]],
                source_ips=[],
            ))
    return results


def detect_new_geo_off_hours(events: list[LogEvent], known_ips: set[str] | None = None,
                              off_hours: tuple[int, int] = (0, 5)) -> list[DetectionResult]:
    """Very light heuristic baseline: successful logins from unrecognized IPs,
    or at off-hours (server local time hour in `off_hours` range)."""
    known_ips = known_ips or set()
    results = []
    for e in events:
        if e.action == "ssh_login" and e.status == "success" and e.source_ip:
            if e.source_ip not in known_ips:
                results.append(DetectionResult(
                    signature=f"new_geo:{e.source_ip}",
                    attack_technique="T1078",  # Valid Accounts
                    title=f"Successful login from previously unseen source {e.source_ip}",
                    description=(
                        f"User '{e.user}' logged in successfully from {e.source_ip}, "
                        f"an IP not in the known/allowlisted set."
                    ),
                    severity="medium",
                    confidence=0.4,
                    evidence_lines=[e.raw],
                    source_ips=[e.source_ip],
                ))
    return results


ALL_DETECTORS = [
    detect_brute_force,
    detect_port_scan,
    detect_injection_probes,
    detect_privilege_escalation,
    detect_log_tampering,
    detect_exfil_volume,
    detect_c2_beaconing,
]


def detect_anomalies(events: list[LogEvent], known_ips: set[str] | None = None) -> list[DetectionResult]:
    results: list[DetectionResult] = []
    for detector in ALL_DETECTORS:
        results.extend(detector(events))
    results.extend(detect_new_geo_off_hours(events, known_ips=known_ips))
    return results
