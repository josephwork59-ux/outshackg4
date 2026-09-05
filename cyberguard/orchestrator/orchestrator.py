"""The supervisor: owns the run lifecycle, never executes remediation."""

from __future__ import annotations

import asyncio
import uuid

from agents import (
    IncidentResponseAgent,
    LogMonitorAgent,
    PolicyCheckerAgent,
    ThreatIntelAgent,
    VulnerabilityScannerAgent,
)
from contracts import AgentResult, ScanReport, ScanTarget, SEVERITY_RANK, utcnow_iso
from llm import get_llm

from .correlate import clusters_for_ir, correlate, dedupe
from .severity import finalize


class Orchestrator:
    def __init__(self, llm=None) -> None:
        self.llm = llm or get_llm()
        self.log_monitor = LogMonitorAgent()
        self.vuln_scanner = VulnerabilityScannerAgent()
        self.threat_intel = ThreatIntelAgent()
        self.incident_response = IncidentResponseAgent(llm=self.llm)
        self.policy_checker = PolicyCheckerAgent()

    async def run(self, target: ScanTarget) -> ScanReport:
        run_id = "scan-" + uuid.uuid4().hex[:10]
        started = utcnow_iso()
        status: dict[str, str] = {}
        notes: dict[str, list[str]] = {}

        # 1-2. Log Monitor and Vulnerability Scanner in parallel.
        log_res, vuln_res = await asyncio.gather(
            asyncio.to_thread(self.log_monitor.run, target),
            asyncio.to_thread(self.vuln_scanner.run, target),
        )
        for res in (log_res, vuln_res):
            status[res.agent] = res.status
            notes[res.agent] = res.notes
        findings = list(log_res.findings) + list(vuln_res.findings)

        # 3. Threat Intelligence enriches and adds its own findings.
        ti_res: AgentResult = await asyncio.to_thread(
            self.threat_intel.enrich_run, findings, target
        )
        status[ti_res.agent] = ti_res.status
        notes[ti_res.agent] = ti_res.notes
        findings = ti_res.findings

        # 4. Deduplicate, correlate, finalize severity.
        findings = dedupe(findings)
        correlations = correlate(findings)
        for f in findings:
            finalize(f, target)
        findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.confidence), reverse=True)

        # 5. Incident Response for confirmed / high-confidence clusters.
        clusters = clusters_for_ir(findings)
        plans = [self.incident_response.plan_for(c, target) for c in clusters]
        status["incident_response"] = "ok"
        notes["incident_response"] = [f"{len(plans)} plan(s) for {len(clusters)} cluster(s)"]

        # 6. Policy / compliance over the full findings set.
        compliance, pol_status, pol_notes = self.policy_checker.run_over(findings, target)
        status["policy_checker"] = pol_status
        notes["policy_checker"] = pol_notes

        # 7. Executive summary.
        exec_summary = self.llm.executive_summary(self._facts(findings, plans, compliance, target))

        report = ScanReport(
            run_id=run_id,
            started_at=started,
            finished_at=utcnow_iso(),
            target_summary=target.summary(),
            findings=findings,
            incident_plans=plans,
            compliance=compliance,
            agent_status=status,
            executive_summary=exec_summary,
        )
        report.target_summary["agent_notes"] = notes
        report.target_summary["correlations"] = correlations
        return report

    @staticmethod
    def _facts(findings, plans, compliance, target) -> dict:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "framework": target.framework,
            "finding_count": len(findings),
            "severity_counts": counts,
            "top_findings": [f"[{f.severity}] {f.title}" for f in findings[:5]],
            "incident_plan_count": len(plans),
            "compliance_coverage_pct": compliance.coverage_pct if compliance else None,
            "failing_control_count": len(compliance.failing_controls) if compliance else 0,
        }


def run_scan(target: ScanTarget, llm=None) -> ScanReport:
    """Synchronous convenience wrapper."""
    return asyncio.run(Orchestrator(llm=llm).run(target))
