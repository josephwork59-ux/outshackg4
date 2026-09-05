from __future__ import annotations

import hashlib
import time

from contracts import Finding, IncidentPlan
from tools.audit import RunAuditLog
from tools.llm_client import LLMClient, get_llm_client

from . import playbooks


class IncidentResponseAgent:
    name = "incident_response"

    def __init__(self, llm: LLMClient | None = None, audit: RunAuditLog | None = None):
        self.llm = llm or get_llm_client()
        self.audit = audit

    def build_plan(self, finding: Finding, correlated: list[Finding] | None = None) -> IncidentPlan:
        t0 = time.time()
        correlated = correlated or []
        steps = playbooks.build_steps(finding)
        priority, sla = playbooks.priority_for(finding)
        impact = playbooks.estimate_impact(finding)
        comms = playbooks.draft_comms(finding)

        narrative = self.llm.complete(
            system="You are an incident commander writing a concise executive note. "
                   "Do not invent facts beyond what is given.",
            prompt=(
                f"Finding: {finding.title}\nSeverity: {finding.severity} Priority: {priority}\n"
                f"Impact estimate: {impact}\nWrite one short paragraph summarizing why this "
                f"matters and what happens if it is not remediated within the SLA."
            ),
            max_tokens=250,
        )

        plan = IncidentPlan(
            id=hashlib.sha256(f"plan:{finding.id}".encode()).hexdigest()[:16],
            finding_id=finding.id,
            finding_ids=[finding.id] + [c.id for c in correlated],
            priority=priority,
            sla_target=sla,
            steps=steps,
            required_approvals=["Security Lead"] + (["Legal/Comms"] if finding.severity == "critical" else []),
            evidence_preservation_checklist=[
                "Raw log/evidence snapshot captured before eradication",
                "Finding evidence lines preserved in the ScanReport (immutable)",
                "Chain-of-custody note added if this becomes a formal investigation",
            ],
            impact_summary=f"{impact}\n\n{narrative}",
            comms_draft=comms,
        )

        if self.audit:
            self.audit.log_agent_output(self.name, "ok", 1, time.time() - t0)
        return plan

    def run(self, findings: list[Finding], min_severity: str = "high",
            min_confidence: float = 0.7) -> list[IncidentPlan]:
        from contracts.models import severity_weight
        threshold = severity_weight(min_severity)  # type: ignore[arg-type]
        plans = []
        for f in findings:
            if severity_weight(f.severity) >= threshold or f.confidence >= min_confidence:
                correlated = [findings[i] for i in range(len(findings))
                              if findings[i].id in f.correlated_ids]
                plans.append(self.build_plan(f, correlated))
        return plans
