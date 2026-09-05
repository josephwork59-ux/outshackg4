from __future__ import annotations

import time

from contracts import Finding
from tools.audit import RunAuditLog
from tools.llm_client import LLMClient, get_llm_client
from tools.redact import redact_lines

from . import parsers
from .detectors import detect_anomalies

SYSTEM_PROMPT_PATH = __file__.replace("agent.py", "system_prompt.md")


class LogMonitorAgent:
    name = "log_monitor"

    def __init__(self, llm: LLMClient | None = None, audit: RunAuditLog | None = None):
        self.llm = llm or get_llm_client()
        self.audit = audit

    def run(self, log_sources: list[str], known_ips: set[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        t0 = time.time()
        all_events = []
        for source in log_sources:
            t_tool = time.time()
            events = parsers.parse_all(source, fmt="auto")
            all_events.extend(events)
            if self.audit:
                self.audit.log_tool_call(
                    self.name, "parse_log", {"source": source}, time.time() - t_tool,
                    f"{len(events)} events parsed",
                )

        t_tool = time.time()
        detections = detect_anomalies(all_events, known_ips=known_ips)
        if self.audit:
            self.audit.log_tool_call(
                self.name, "detect_anomalies", {"n_events": len(all_events)},
                time.time() - t_tool, f"{len(detections)} detections",
            )

        for d in detections:
            evidence = redact_lines(d.evidence_lines)
            findings.append(Finding.new(
                agent=self.name,
                title=d.title,
                description=d.description,
                severity=d.severity,  # type: ignore[arg-type]
                confidence=d.confidence,
                category=f"ATT&CK:{d.attack_technique}",
                target=",".join(log_sources),
                signature=d.signature,
                evidence=evidence,
                references=[f"https://attack.mitre.org/techniques/{d.attack_technique.replace('.', '/')}/"],
                recommended_fix=self._recommend_fix(d.signature),
                requires_human_approval=True,
            ))

        if self.audit:
            self.audit.log_agent_output(self.name, "ok", len(findings), time.time() - t0)
        return findings

    @staticmethod
    def _recommend_fix(signature: str) -> str:
        if signature.startswith("brute_force"):
            return "Enforce account lockout / rate limiting on SSH; require key-based auth; consider fail2ban."
        if signature.startswith("scan"):
            return "Review WAF/firewall rules; ensure only necessary paths are exposed; add rate limiting."
        if signature.startswith("injection"):
            return "Validate/sanitize input server-side; use parameterized queries; deploy/update WAF rules."
        if signature.startswith("priv_esc"):
            return "Audit sudoers and group membership; investigate the responsible account immediately."
        if signature.startswith("log_tampering"):
            return "Restore logging service; forward logs to an immutable/remote sink; investigate the host."
        if signature.startswith("exfil"):
            return "Investigate destination of the large transfer; apply DLP egress controls."
        if signature.startswith("c2_beacon"):
            return "Isolate the host; block the destination; capture memory/network forensics before remediation."
        if signature.startswith("new_geo"):
            return "Confirm with the user this login is legitimate; consider requiring MFA / geo-fencing."
        return "Review the finding with a security analyst."
