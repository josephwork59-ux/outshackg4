"""Policy Checker Agent - map findings to ISO 27001 / NIST CSF / SOC 2 controls.

Uses a bundled, clearly-labelled SUBSET of each framework. Reports, per control:
Met / Partial / Not Met / Not Assessed, with the finding IDs used as evidence,
a remediation, and a rough effort estimate. Never claims a "pass" without cited
evidence.
"""

from __future__ import annotations

import json
import os
from typing import Any

from contracts import (
    AgentResult,
    ComplianceReport,
    ControlAssessment,
    Finding,
    ScanTarget,
    SEVERITY_RANK,
)

from .base import DATA_DIR, Agent

_FRAMEWORK_FILE = {
    "NIST_CSF": "nist_csf.json",
    "NIST": "nist_csf.json",
    "SOC2": "soc2.json",
    "SOC_2": "soc2.json",
    "ISO27001": "iso27001.json",
    "ISO_27001": "iso27001.json",
}

_EFFORT_BY_SEVERITY = {
    "critical": "M (days) - coordinated change",
    "high": "M (days)",
    "medium": "S (hours-day)",
    "low": "S (hours)",
    "info": "XS",
}


class PolicyCheckerAgent(Agent):
    name = "policy_checker"
    role = "Check the setup against ISO, NIST, or SOC 2 and show where fixes are needed."
    system_prompt = (
        "You are the Policy Checker Agent. Given a framework and the full findings set, "
        "map each finding to the controls it bears on, then assess each control as Met / "
        "Partial / Not Met / Not Assessed with a one-line rationale and the evidence used. "
        "Do not claim a control is Met without positive evidence. Always state the "
        "framework version and that only a control subset was evaluated. Output a gap "
        "list with remediation and effort."
    )

    def __init__(self, data_dir: str = DATA_DIR) -> None:
        self.controls_dir = os.path.join(data_dir, "controls")

    def assess(self, findings: list[Finding], framework: str) -> ComplianceReport:
        fname = _FRAMEWORK_FILE.get(framework.upper().replace("-", "_"))
        if not fname:
            raise ValueError(f"unknown framework {framework!r}; expected one of {sorted(set(_FRAMEWORK_FILE))}")
        with open(os.path.join(self.controls_dir, fname), encoding="utf-8") as fh:
            spec = json.load(fh)

        controls = spec["controls"]
        matrix: dict[str, list[str]] = {}
        assessments: list[ControlAssessment] = []
        failing: list[str] = []
        backlog: list[dict] = []

        for ctrl in controls:
            mapped = [f for f in findings if self._maps(f, ctrl)]
            for f in mapped:
                matrix.setdefault(f.id, [])
                if ctrl["id"] not in matrix[f.id]:
                    matrix[f.id].append(ctrl["id"])

            if not mapped:
                assessments.append(ControlAssessment(
                    control_id=ctrl["id"],
                    title=ctrl["title"],
                    status="Not Assessed",
                    rationale="No finding bears on this control and no positive evidence was collected offline.",
                ))
                continue

            worst = max(mapped, key=lambda f: SEVERITY_RANK[f.severity])
            open_serious = [f for f in mapped if SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"]]
            status = "Not Met" if open_serious else "Partial"
            rationale = (
                f"{len(mapped)} related finding(s); worst severity '{worst.severity}'. "
                + ("One or more high/critical issues make this control Not Met."
                   if open_serious else "Only medium/low issues - control partially effective.")
            )
            ca = ControlAssessment(
                control_id=ctrl["id"],
                title=ctrl["title"],
                status=status,
                rationale=rationale,
                evidence_finding_ids=sorted({f.id for f in mapped}),
                remediation="; ".join(sorted({f.recommended_fix for f in mapped if f.recommended_fix}))[:600]
                or "Remediate the mapped findings.",
                effort=_EFFORT_BY_SEVERITY[worst.severity],
            )
            assessments.append(ca)
            failing.append(ctrl["id"])
            backlog.append({
                "control_id": ctrl["id"],
                "title": ctrl["title"],
                "status": status,
                "worst_severity": worst.severity,
                "finding_ids": ca.evidence_finding_ids,
                "remediation": ca.remediation,
                "effort": ca.effort,
            })

        backlog.sort(key=lambda b: SEVERITY_RANK[b["worst_severity"]], reverse=True)
        assessed = [a for a in assessments if a.status != "Not Assessed"]
        coverage = round(100.0 * len(assessed) / len(controls), 1) if controls else 0.0

        return ComplianceReport(
            framework=spec["framework"],
            framework_version=spec["version"],
            subset_note=spec.get("subset_note", "Representative subset only."),
            evaluated_controls=len(controls),
            coverage_pct=coverage,
            assessments=assessments,
            failing_controls=failing,
            remediation_backlog=backlog,
            finding_control_matrix=matrix,
        )

    def run_over(self, findings: list[Finding], target: ScanTarget) -> tuple[ComplianceReport | None, str, list[str]]:
        try:
            report = self.assess(findings, target.framework)
            return report, "ok", [
                f"assessed {report.evaluated_controls} controls of {report.framework} {report.framework_version}; "
                f"{len(report.failing_controls)} failing/partial"
            ]
        except Exception as exc:  # noqa: BLE001
            return None, "failed", [f"{type(exc).__name__}: {exc}"]

    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:
        report, status, notes = self.run_over(list(context.get("findings", [])), target)
        context["_compliance"] = report
        return AgentResult(self.name, [], status, notes)

    @staticmethod
    def _maps(f: Finding, ctrl: dict) -> bool:
        cats = {c.lower() for c in ctrl.get("categories", [])}
        fcat = f.category.lower()
        if fcat:
            if fcat in cats:
                return True
            # "CVE" category token matches any concrete CVE id
            if "cve" in cats and fcat.startswith("cve-"):
                return True
            for c in cats:
                if c and (c in fcat or fcat.startswith(c + "-") or fcat.startswith(c)):
                    return True
        blob = f"{f.title} {f.description} {f.category}".lower()
        return any(kw.lower() in blob for kw in ctrl.get("keywords", []))
