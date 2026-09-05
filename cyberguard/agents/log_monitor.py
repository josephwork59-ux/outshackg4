"""Log Monitor Agent - detect unusual activity or attacks in system/network logs."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import unquote_plus

from contracts import AgentResult, Finding, ScanTarget
from tools.logparse import Event, iter_events
from tools.redaction import redact_lines

from .base import Agent

# --- signature config -------------------------------------------------------

BRUTEFORCE_MIN_FAILURES = 5  # failures from one source IP before we alert

_WEB_ATTACK_PATTERNS: list[tuple[str, str, str]] = [
    # (label, ATT&CK-ish category, regex)
    ("SQL injection probe", "OWASP-A03 / ATT&CK T1190", r"(?i)(union\s+select|'\s+or\s+'?1'?\s*=\s*'?1|sleep\(\d|benchmark\(|information_schema|--\s|%27|xp_cmdshell)"),
    ("XSS probe", "OWASP-A03 / ATT&CK T1190", r"(?i)(<script\b|onerror\s*=|javascript:|%3cscript)"),
    ("Path traversal / LFI probe", "OWASP-A01 / ATT&CK T1190", r"(\.\./){2,}|/etc/passwd|\.\.%2f|/proc/self/environ"),
    ("Command injection probe", "OWASP-A03 / ATT&CK T1190", r"(?i)(;\s*(cat|wget|curl|nc|bash)\s|%3b|\|\s*sh\b|\$\(.*\))"),
    ("Known scanner user-agent", "ATT&CK T1595", r"(?i)(sqlmap|nikto|acunetix|nmap|masscan|dirbuster|gobuster|wpscan)"),
]

_LOG_TAMPER = re.compile(
    r"(?i)(journal(?:d)? stopped|rsyslogd.*exiting on signal|audit.*cleared"
    r"|history -c|truncate -s 0 .*log|rm -f /var/log)"
)
_SUDO_ABUSE = re.compile(
    r"(?i)(not in the sudoers|incorrect password attempts|authentication failure.*sudo"
    r"|sudo:session.*root)"
)


class LogMonitorAgent(Agent):
    name = "log_monitor"
    role = "Read system and network logs to detect unusual activity or attacks."
    system_prompt = (
        "You are the Log Monitor Agent in a multi-agent SOC. You are given normalized "
        "log events. Identify brute-force/credential-stuffing, scanning, injection "
        "probes, privilege escalation, and log tampering. For every detection, cite the "
        "exact log lines (already redacted), name the source IP(s) and time window, add "
        "the MITRE ATT&CK technique where known, and give a calibrated confidence. "
        "Never modify logs. Never assert an attack succeeded without evidence of success."
    )

    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:
        notes: list[str] = []
        if not target.log_sources:
            return AgentResult(self.name, [], "partial", ["no log sources configured"])

        events: list[Event] = []
        read_ok = 0
        for src in target.log_sources:
            path = src.get("path")
            fmt = src.get("format", "auto")
            if not path:
                continue
            try:
                src_events = list(iter_events(path, fmt=fmt))
                events.extend(src_events)
                read_ok += 1
                notes.append(f"read {len(src_events)} events from {path}")
            except OSError as exc:
                notes.append(f"could not read {path}: {exc}")

        if read_ok == 0:
            return AgentResult(self.name, [], "failed", notes or ["no readable log sources"])

        findings: list[Finding] = []
        findings.extend(self._brute_force(events))
        findings.extend(self._web_attacks(events))
        findings.extend(self._priv_esc(events))
        findings.extend(self._log_tamper(events))

        status = "ok" if read_ok == len(target.log_sources) else "partial"
        return AgentResult(self.name, findings, status, notes)

    # --- detectors --------------------------------------------------------

    def _brute_force(self, events: list[Event]) -> list[Finding]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        success_after: dict[str, bool] = defaultdict(bool)
        for ev in events:
            if ev.kind == "auth_fail" and ev.source_ip:
                by_ip[ev.source_ip].append(ev)
            elif ev.kind == "auth_ok" and ev.source_ip and by_ip.get(ev.source_ip):
                success_after[ev.source_ip] = True

        findings: list[Finding] = []
        for ip, evs in by_ip.items():
            if len(evs) < BRUTEFORCE_MIN_FAILURES:
                continue
            breached = success_after[ip]
            sev = "critical" if breached else "high"
            conf = min(0.95, 0.55 + 0.03 * len(evs) + (0.2 if breached else 0.0))
            window = f"{evs[0].ts or '?'} .. {evs[-1].ts or '?'}"
            findings.append(
                Finding(
                    agent=self.name,
                    title=f"Brute-force / credential-stuffing from {ip} "
                    f"({len(evs)} failed auth attempts)"
                    + (" followed by a SUCCESSFUL login" if breached else ""),
                    description=(
                        f"{len(evs)} failed authentication events from {ip} between {window}. "
                        + (
                            "A successful authentication from the same IP was observed afterwards - "
                            "treat the account as potentially compromised."
                            if breached
                            else "No successful login from this IP was observed."
                        )
                    ),
                    severity=sev,
                    confidence=conf,
                    category="ATT&CK T1110" + (".001" if not breached else ""),
                    target=evs[0].source,
                    signature=f"bruteforce:{ip}",
                    evidence=redact_lines([e.raw for e in evs[:6]]),
                    references=["https://attack.mitre.org/techniques/T1110/"],
                    recommended_fix=(
                        "Block the source IP at the edge, lock/reset the targeted account(s), "
                        "enforce MFA, and deploy rate-limiting / fail2ban on the auth service."
                    ),
                    enrichment={"source_ip": ip, "failure_count": len(evs), "breached": breached},
                )
            )
        return findings

    def _web_attacks(self, events: list[Event]) -> list[Finding]:
        hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            if ev.kind != "http":
                continue
            raw_hay = f"{ev.http_path or ''} {ev.fields.get('ua', '')} {ev.fields.get('referer', '')}"
            haystack = raw_hay + " " + unquote_plus(raw_hay)
            for label, category, pattern in _WEB_ATTACK_PATTERNS:
                if re.search(pattern, haystack):
                    hits[(label, category)].append(ev)

        findings: list[Finding] = []
        for (label, category), evs in hits.items():
            ips = sorted({e.source_ip for e in evs if e.source_ip})
            success = any((e.http_status or 0) < 400 for e in evs)
            recon_only = label == "Known scanner user-agent"
            sev = "medium" if recon_only else ("high" if success else "medium")
            findings.append(
                Finding(
                    agent=self.name,
                    title=f"{label}: {len(evs)} request(s) from {', '.join(ips) or 'unknown'}",
                    description=(
                        f"{len(evs)} HTTP request(s) matched the '{label}' signature. "
                        + (
                            "Reconnaissance tooling - not an exploit attempt on its own, but expect follow-up."
                            if recon_only
                            else "At least one received a non-error (<400) response - possible successful exploitation, investigate."
                            if success
                            else "All matched requests received error responses."
                        )
                    ),
                    severity=sev,
                    confidence=0.55 if recon_only else (0.7 if success else 0.55),
                    category=category,
                    target=evs[0].source,
                    signature=f"webattack:{label}:{','.join(ips)}",
                    evidence=redact_lines([e.raw for e in evs[:6]]),
                    references=["https://attack.mitre.org/techniques/T1190/"],
                    recommended_fix=(
                        "Add/verify a WAF rule for this payload class, rate-limit or block the "
                        "source, and audit the targeted endpoint for the underlying injection flaw."
                    ),
                    enrichment={"source_ips": ips, "possible_success": success},
                )
            )
        return findings

    def _priv_esc(self, events: list[Event]) -> list[Finding]:
        evs = [e for e in events if _SUDO_ABUSE.search(e.raw)]
        if not evs:
            return []
        ips = sorted({e.source_ip for e in evs if e.source_ip})
        return [
            Finding(
                agent=self.name,
                title=f"Privilege-escalation attempts via sudo ({len(evs)} event(s))",
                description="Repeated sudo authentication failures or use by a user not in sudoers.",
                severity="medium",
                confidence=0.6,
                category="ATT&CK T1548.003",
                target=evs[0].source,
                signature="privesc:sudo",
                evidence=redact_lines([e.raw for e in evs[:6]]),
                references=["https://attack.mitre.org/techniques/T1548/003/"],
                recommended_fix="Review sudoers, alert on repeated failures, and confirm the account owner.",
                enrichment={"source_ips": ips},
            )
        ]

    def _log_tamper(self, events: list[Event]) -> list[Finding]:
        evs = [e for e in events if _LOG_TAMPER.search(e.raw)]
        if not evs:
            return []
        return [
            Finding(
                agent=self.name,
                title="Possible log tampering / anti-forensics activity",
                description="Log lines indicate logging services were stopped or log files cleared/truncated.",
                severity="high",
                confidence=0.6,
                category="ATT&CK T1070",
                target=evs[0].source,
                signature="logtamper",
                evidence=redact_lines([e.raw for e in evs[:6]]),
                references=["https://attack.mitre.org/techniques/T1070/"],
                recommended_fix="Ship logs off-host immediately, preserve current state, and investigate for prior compromise.",
            )
        ]
