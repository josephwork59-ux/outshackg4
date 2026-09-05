from __future__ import annotations

import time

from contracts import ComplianceReport, ControlAssessment, Finding, IncidentPlan
from tools.audit import RunAuditLog
from tools.llm_client import LLMClient, get_llm_client

from .controls_nist_csf import CONTROL_SUBSET_NOTE, FRAMEWORK_NAME, FRAMEWORK_VERSION, Control, load_controls


class PolicyCheckerAgent:
    name = "policy_checker"

    def __init__(self, llm: LLMClient | None = None, audit: RunAuditLog | None = None):
        self.llm = llm or get_llm_client()
        self.audit = audit

    def run(self, findings: list[Finding], incident_plans: list[IncidentPlan],
            framework: str = "NIST CSF 2.0") -> ComplianceReport:
        t0 = time.time()
        controls = load_controls(framework)
        assessments = [
            self._assess(c, findings, incident_plans) for c in controls
        ]
        evaluated = [a for a in assessments if a.status != "N/A"]
        met = [a for a in evaluated if a.status == "Met"]
        coverage = (len(met) / len(evaluated) * 100) if evaluated else 0.0

        report = ComplianceReport(
            framework=FRAMEWORK_NAME,
            framework_version=FRAMEWORK_VERSION,
            control_subset_note=CONTROL_SUBSET_NOTE,
            coverage_percent=round(coverage, 1),
            assessments=assessments,
        )
        if self.audit:
            self.audit.log_agent_output(self.name, "ok", len(assessments), time.time() - t0)
        return report

    def _relevant_findings(self, control: Control, findings: list[Finding]) -> list[Finding]:
        out = []
        for f in findings:
            if f.agent not in control.relevant_agents:
                continue
            if control.category_keywords and not any(
                kw.lower() in f.category.lower() or kw.lower() in f.title.lower()
                for kw in control.category_keywords
            ):
                continue
            out.append(f)
        return out

    def _assess(self, control: Control, findings: list[Finding],
                plans: list[IncidentPlan]) -> ControlAssessment:
        if control.control_id == "RS.MA-01":
            return self._assess_response_plans(control, plans, phase_required=False)
        if control.control_id == "RC.RP-01":
            return self._assess_response_plans(control, plans, phase_required=True)
        if control.control_id == "GV.RM-01":
            # Governance control: evidenced by the mere existence of this
            # multi-agent risk pipeline having run, not by absence of findings.
            return ControlAssessment(
                control_id=control.control_id, control_name=control.name, status="Met",
                rationale="A structured risk-identification pipeline (this system) executed "
                          "and produced a findings inventory for review.",
                evidence_finding_ids=[], remediation="", effort_estimate="",
            )

        relevant = self._relevant_findings(control, findings)
        t0 = time.time()
        if not relevant:
            status = "Met" if control.pass_on_no_findings else "N/A"
            rationale = (
                "No relevant findings from this run — treated as passing evidence for a "
                "'no known issues' control." if status == "Met"
                else "No findings from the relevant agent(s) in this run to evaluate this control against."
            )
            result = ControlAssessment(
                control_id=control.control_id, control_name=control.name, status=status,
                rationale=rationale, evidence_finding_ids=[], remediation="", effort_estimate="",
            )
        else:
            bad = [f for f in relevant if f.severity in ("critical", "high")]
            if bad:
                status = "Not Met"
            elif any(f.severity == "medium" for f in relevant):
                status = "Partial"
            else:
                status = "Met" if control.pass_on_no_findings else "Partial"
            rationale = (
                f"{len(relevant)} relevant finding(s) from {sorted({f.agent for f in relevant})}: "
                f"{len(bad)} at high/critical severity."
            )
            result = ControlAssessment(
                control_id=control.control_id, control_name=control.name, status=status,
                rationale=rationale,
                evidence_finding_ids=[f.id for f in relevant],
                remediation="; ".join(sorted({f.recommended_fix for f in relevant if f.recommended_fix}))[:500],
                effort_estimate=self._effort_estimate(len(relevant), status),
            )
        if self.audit:
            self.audit.log_tool_call(self.name, "assess_control", {"control_id": control.control_id},
                                      time.time() - t0, result.status)
        return result

    def _assess_response_plans(self, control: Control, plans: list[IncidentPlan],
                                phase_required: bool) -> ControlAssessment:
        if not plans:
            return ControlAssessment(
                control_id=control.control_id, control_name=control.name, status="N/A",
                rationale="No high-confidence findings this run required an incident plan.",
                evidence_finding_ids=[], remediation="", effort_estimate="",
            )
        if phase_required:
            ok = all(any(s.phase.value == "recover" for s in p.steps) for p in plans)
        else:
            ok = all(len(p.steps) >= 4 for p in plans)  # all 4 phases present
        return ControlAssessment(
            control_id=control.control_id, control_name=control.name,
            status="Met" if ok else "Partial",
            rationale=f"{len(plans)} incident plan(s) generated; phase completeness check {'passed' if ok else 'incomplete'}.",
            evidence_finding_ids=[p.finding_id for p in plans],
            remediation="" if ok else "Ensure every incident plan includes all four IR phases.",
            effort_estimate="low" if ok else "medium",
        )

    @staticmethod
    def _effort_estimate(n_findings: int, status: str) -> str:
        if status == "Met":
            return ""
        if n_findings >= 5:
            return "high"
        if n_findings >= 2:
            return "medium"
        return "low"
