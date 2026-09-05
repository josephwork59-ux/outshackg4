"""Deterministic phase-template generation, keyed by finding category /
signature family. The LLM (in agent.py) only narrates impact/comms text —
the actual phased steps come from these templates so plans stay consistent
and auditable across runs of the same finding type.
"""
from __future__ import annotations

from contracts import Finding, IncidentPhase, IncidentStep

_PRIORITY_BY_SEVERITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}
_SLA_BY_PRIORITY = {"P1": "1 hour", "P2": "4 hours", "P3": "1 business day", "P4": "1 week"}


def priority_for(finding: Finding) -> tuple[str, str]:
    priority = _PRIORITY_BY_SEVERITY.get(finding.severity, "P3")
    return priority, _SLA_BY_PRIORITY[priority]


def _generic_steps(finding: Finding) -> list[IncidentStep]:
    return [
        IncidentStep(
            phase=IncidentPhase.CONTAIN, order=1,
            description="Preserve evidence and isolate the affected asset/account.",
            owner_role="SOC Analyst",
            command_or_change=f"Snapshot logs/disk for target `{finding.target}`; disable/rotate credentials if account-related.",
            rollback="Re-enable account/asset once forensic snapshot is confirmed complete.",
            verification="Confirm snapshot exists and asset is isolated (no new traffic in/out).",
        ),
        IncidentStep(
            phase=IncidentPhase.ERADICATE, order=2,
            description="Remove the root cause identified in the finding.",
            owner_role="Security Engineer",
            command_or_change=finding.recommended_fix or "Apply the recommended fix from the finding.",
            rollback="Revert the change from a tested backup/staging config if it breaks the service.",
            verification="Re-run the originating scanner/detector; confirm the finding no longer triggers.",
        ),
        IncidentStep(
            phase=IncidentPhase.RECOVER, order=3,
            description="Restore normal service and monitor for recurrence.",
            owner_role="On-call Engineer",
            command_or_change=f"Re-enable `{finding.target}`; add targeted monitoring/alert for this signature.",
            rollback="Re-isolate if anomalous activity resumes.",
            verification="24h of clean monitoring with no repeat detections for this signature.",
        ),
        IncidentStep(
            phase=IncidentPhase.POST_INCIDENT, order=4,
            description="Document root cause and update detections/controls.",
            owner_role="Security Lead",
            command_or_change="Write post-incident report; update detection rule or scanner policy if this was a gap.",
            rollback="N/A (documentation step).",
            verification="Post-incident report reviewed and filed; ticket closed.",
        ),
    ]


def build_steps(finding: Finding) -> list[IncidentStep]:
    steps = _generic_steps(finding)
    if finding.agent == "log_monitor" and "brute_force" in finding.category.lower() or "T1110" in finding.category:
        steps[0].command_or_change = (
            f"Block source IP(s) at the firewall/WAF (proposal only); "
            f"force password reset for targeted accounts; enable MFA."
        )
    if "secret" in finding.title.lower() or finding.category == "CWE-798":
        steps[1].command_or_change = "Revoke and rotate the exposed credential; purge from git history (BFG/git-filter-repo); audit access logs for misuse."
        steps[0].description = "Preserve evidence of exposure window; assume the credential is compromised immediately."
    return steps


def estimate_impact(finding: Finding) -> str:
    scope = "a single asset/endpoint" if ":" in finding.target else "the named target"
    data_risk = "credentials or session data" if "auth" in finding.category.lower() or finding.agent == "log_monitor" else "application/infrastructure integrity"
    reg_exposure = "Possible regulatory notification obligation if customer data was exposed." if finding.severity in ("critical", "high") else "Low regulatory exposure at current severity."
    return (
        f"Blast radius: {scope} ({finding.target}). Data at risk: {data_risk}. "
        f"{reg_exposure} Confidence in this finding: {finding.confidence:.0%}."
    )


def draft_comms(finding: Finding) -> str:
    return (
        f"INTERNAL NOTICE — {finding.severity.upper()} finding on {finding.target}\n"
        f"Summary: {finding.title}.\n"
        f"Status: under investigation, remediation proposed, awaiting approval.\n"
        f"No external disclosure drafted automatically — escalate to Legal/Comms "
        f"if customer data exposure is confirmed."
    )
