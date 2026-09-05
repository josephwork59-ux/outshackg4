from __future__ import annotations

import time

from contracts import Finding
from tools.audit import RunAuditLog
from tools.llm_client import LLMClient, get_llm_client

from .feeds import ThreatFeed, get_default_feed


class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(self, feed: ThreatFeed | None = None, llm: LLMClient | None = None,
                 audit: RunAuditLog | None = None):
        self.feed = feed or get_default_feed()
        self.llm = llm or get_llm_client()
        self.audit = audit

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        """Enrich in place (returns the same list, mutated) — CVE findings get
        CVSS/EPSS/KEV/affected reasoning; log-monitor findings with source IPs
        get IOC reputation folded into their evidence/description."""
        t0 = time.time()
        enriched = 0
        for f in findings:
            if f.cve_ids:
                self._enrich_cve_finding(f)
                enriched += 1
            elif f.agent == "log_monitor":
                self._enrich_ioc_finding(f)

        if self.audit:
            self.audit.log_agent_output(self.name, "ok", enriched, time.time() - t0)
        return findings

    def _enrich_cve_finding(self, f: Finding) -> None:
        for cve_id in f.cve_ids:
            t_tool = time.time()
            rec = self.feed.lookup_cve(cve_id)
            if self.audit:
                self.audit.log_tool_call(self.name, "lookup_cve", {"cve_id": cve_id},
                                          time.time() - t_tool, f"found={rec.found}")

            if not rec.found:
                f.affected = "uncertain"
                f.description += (
                    f"\n\n[threat-intel] No feed data found for {cve_id}; "
                    f"affected status uncertain — verify manually."
                )
                continue

            f.cvss = rec.cvss
            f.epss = rec.epss
            f.kev = rec.kev
            f.exploited_in_wild = rec.exploited_in_wild
            f.references.append(rec.source_url)

            # Deterministic affected decision: version comparison is the
            # scanner's job (it already matched installed_version -> vuln);
            # the LLM only explains *why*, it doesn't re-decide match/no-match.
            f.affected = "yes"
            if rec.fixed_version and rec.fixed_version not in f.recommended_fix:
                f.recommended_fix = f"Upgrade to {rec.fixed_version} (per threat-intel feed)."

            staleness_note = " [STALE feed data >7 days old]" if rec.is_stale else ""
            severity_bump = ""
            if rec.kev:
                severity_bump = " This CVE is on the CISA Known Exploited Vulnerabilities list — treat as active risk, not theoretical."
                f.severity = "critical"

            prompt = (
                f"CVE: {cve_id}\nCVSS: {rec.cvss}  EPSS: {rec.epss}  KEV: {rec.kev}  "
                f"Exploited in wild: {rec.exploited_in_wild}\nSummary: {rec.summary}\n"
                f"Affected package/target: {f.target}\n"
                "Write a 2-3 sentence analyst note on urgency and exploit maturity, "
                "grounded only in the facts above."
            )
            note = self.llm.complete(
                system="You are a threat intelligence analyst. Be precise and factual; "
                       "never invent a CVSS/EPSS number not given to you.",
                prompt=prompt, max_tokens=300,
            )
            f.description += f"\n\n[threat-intel]{staleness_note}{severity_bump}\n{note}"

    def _enrich_ioc_finding(self, f: Finding) -> None:
        # source IPs were embedded in evidence text by the log monitor; we
        # look them up via the `target`/evidence heuristically for the demo.
        import re
        ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", " ".join(f.evidence)))
        for ip in ips:
            t_tool = time.time()
            rec = self.feed.enrich_ioc(ip, "ip")
            if self.audit:
                self.audit.log_tool_call(self.name, "enrich_ioc", {"ip": ip},
                                          time.time() - t_tool, f"malicious={rec.malicious}")
            if rec.found and rec.malicious:
                f.references.append(rec.source_url)
                f.description += (
                    f"\n\n[threat-intel] {ip} matches known campaign "
                    f"'{rec.campaign}' (confidence {rec.confidence:.2f}, source {rec.source_url})."
                )
                if f.confidence < 0.9:
                    f.confidence = min(f.confidence + 0.15, 0.95)
