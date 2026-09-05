"""Incident Response Agent - turn a confirmed finding (or cluster) into a plan.

Proposes only. Every state-changing step is flagged `requires_human_approval`.
Plans follow the NIST SP 800-61 lifecycle: Contain -> Eradicate -> Recover ->
Post-incident, and always start by preserving evidence.
"""

from __future__ import annotations

from typing import Any

from contracts import (
    AgentResult,
    Finding,
    IncidentPlan,
    IncidentStep,
    ScanTarget,
    SEVERITY_RANK,
    severity_from_rank,
)
from llm import get_llm

from .base import Agent

_PRIORITY = {
    "critical": ("P1", "Begin containment within 1 hour"),
    "high": ("P2", "Begin containment within 4 hours"),
    "medium": ("P3", "Remediate within 2 business days"),
    "low": ("P4", "Track in the normal backlog"),
    "info": ("P4", "No SLA"),
}

_EVIDENCE_PRESERVATION = [
    "Snapshot affected host(s) / container(s) before making changes.",
    "Export the relevant raw logs to write-once storage and record SHA-256 hashes.",
    "Capture volatile state (process list, network connections) if a host may be compromised.",
    "Record a timeline: who did what, when, in the incident ticket.",
]


def _steps_for(category: str, title: str) -> list[IncidentStep]:
    c = (category + " " + title).lower()

    if "t1110" in c or "brute" in c or "credential" in c:
        return [
            IncidentStep("contain", "Block the offending source IP(s) at the edge / WAF", "Network / SecOps",
                         "Add deny rule for the source IP(s) on the perimeter firewall or WAF",
                         "Remove the deny rule once the campaign subsides", "No further auth attempts from the IP in logs"),
            IncidentStep("contain", "Lock or force-reset the targeted account(s) and revoke active sessions", "IAM",
                         "Disable account / expire password / revoke tokens & sessions",
                         "Re-enable after owner verification", "Owner confirms control; no unexpected sessions remain"),
            IncidentStep("eradicate", "Rotate credentials for any account with a successful login after failures", "IAM",
                         "Reset password + rotate API keys / tokens for the account",
                         "n/a", "Old credentials rejected; new ones issued to verified owner"),
            IncidentStep("eradicate", "Review auth logs for successful logins from the source and for lateral movement", "SOC",
                         "", "n/a", "Analyst sign-off that scope is understood", requires_human_approval=False),
            IncidentStep("recover", "Restore normal access for verified users; keep heightened monitoring 7 days", "IAM / SOC",
                         "", "n/a", "Users can log in; alerting tuned"),
            IncidentStep("post-incident", "Enforce MFA, tune lockout thresholds, deploy fail2ban/rate-limiting, add a detection rule", "Platform",
                         "", "n/a", "Controls deployed and tested"),
        ]

    if "t1190" in c or "injection" in c or "xss" in c or "sqli" in c or "traversal" in c or "probe" in c:
        return [
            IncidentStep("contain", "Deploy/verify a WAF rule for the payload class and rate-limit the source", "AppSec / Network",
                         "Enable managed WAF ruleset (e.g. OWASP CRS) for the affected route",
                         "Loosen rule if false positives appear", "Malicious requests blocked; legitimate traffic unaffected"),
            IncidentStep("eradicate", "Patch the underlying injection/traversal flaw in the endpoint", "App team",
                         "Parameterize queries / validate & canonicalize input / apply output encoding",
                         "Revert the deploy", "Exploit request no longer succeeds in a test"),
            IncidentStep("eradicate", "Review app and DB logs for successful exploitation and data access", "SOC / DBA",
                         "", "n/a", "Analyst sign-off on impact scope", requires_human_approval=False),
            IncidentStep("recover", "Redeploy the patched service and confirm functionality", "App team",
                         "", "Roll back to previous known-good build", "Regression tests pass; endpoint healthy"),
            IncidentStep("post-incident", "Add SAST/DAST gates to CI and a regression test for this payload", "AppSec",
                         "", "n/a", "CI blocks a reintroduction of the flaw"),
        ]

    if "cve-" in c or "vulnerable dependency" in c or "osv:" in c or "high-risk" in c:
        return [
            IncidentStep("contain", "Assess exposure; if internet-facing, apply a virtual patch / WAF mitigation", "AppSec",
                         "Add mitigating WAF rule or disable the vulnerable feature/route",
                         "Remove mitigation after upgrade", "Exploit path blocked or unreachable"),
            IncidentStep("eradicate", "Upgrade the affected package to the fixed version and rebuild artifacts/images", "App team",
                         "Bump the pinned version to >= fixed release; rebuild and re-scan",
                         "Pin back to previous version", "Scanner reports the CVE resolved"),
            IncidentStep("recover", "Deploy the rebuilt service and run regression + smoke tests", "App team",
                         "", "Roll back to previous build", "Service healthy; version confirmed in runtime"),
            IncidentStep("post-incident", "Enable automated dependency updates (Dependabot/Renovate) and SCA in CI", "Platform",
                         "", "n/a", "New advisories open PRs automatically; CI fails on known-vuln deps"),
        ]

    if "cwe-798" in c or "secret" in c or "credential" in c:
        return [
            IncidentStep("contain", "Revoke / rotate the exposed credential immediately and invalidate sessions", "Owning team",
                         "Revoke the key/token at the provider; issue a replacement via the secrets manager",
                         "n/a", "Old credential returns 401/403; new one works"),
            IncidentStep("eradicate", "Remove the secret from the repository and its git history", "Owning team",
                         "git filter-repo / BFG to purge; force-push; add a pre-commit secret scanner",
                         "n/a", "Secret absent from all branches and history; pre-commit hook active"),
            IncidentStep("eradicate", "Review provider/audit logs for misuse of the old credential", "SOC",
                         "", "n/a", "Analyst sign-off on misuse assessment", requires_human_approval=False),
            IncidentStep("recover", "Confirm the replacement credential is in use everywhere it is needed", "Owning team",
                         "", "n/a", "All consumers healthy on the new secret"),
            IncidentStep("post-incident", "Move secrets to a manager; add CI secret scanning; brief the team", "Platform",
                         "", "n/a", "No plaintext secrets in repos; CI gate enforced"),
        ]

    if "cwe-250" in c or "cwe-494" in c or "cwe-1188" in c or "cwe-295" in c or "dockerfile" in c or "image" in c or "misconfig" in c:
        return [
            IncidentStep("contain", "Assess whether affected containers are running in production; restrict exposure", "Platform",
                         "Apply network policy / scale down non-essential exposure",
                         "Restore exposure after fix", "Blast radius reduced and documented"),
            IncidentStep("eradicate", "Fix the Dockerfile/image (non-root USER, pinned digest, no remote ADD, TLS verify on) and rebuild", "Platform",
                         "Edit Dockerfile; rebuild; re-scan the image",
                         "Redeploy previous image", "Re-scan shows the misconfiguration resolved"),
            IncidentStep("recover", "Roll the hardened image out across environments", "Platform",
                         "", "Roll back to previous image", "All workloads on the hardened image; healthy"),
            IncidentStep("post-incident", "Add hadolint/trivy config checks to CI and an admission policy (e.g. no :latest, no root)", "Platform",
                         "", "n/a", "CI and admission controller reject non-compliant images"),
        ]

    # generic fallback
    return [
        IncidentStep("contain", "Limit exposure of the affected asset while the issue is investigated", "Asset owner",
                     "Apply the least-disruptive mitigation available", "Remove mitigation after fix", "Exposure reduced"),
        IncidentStep("eradicate", "Apply the fix recommended in the finding", "Asset owner",
                     "See finding.recommended_fix", "Revert the change", "Re-scan confirms resolution"),
        IncidentStep("recover", "Return the asset to normal operation with monitoring", "Asset owner",
                     "", "n/a", "Asset healthy"),
        IncidentStep("post-incident", "Add a detection/prevention control and document lessons learned", "Security",
                     "", "n/a", "Control in place"),
    ]


class IncidentResponseAgent(Agent):
    name = "incident_response"
    role = "Create step-by-step action plans when an issue is found."
    system_prompt = (
        "You are the Incident Response Agent. Given one confirmed or high-confidence "
        "finding (or a correlated cluster) plus environment context, produce a phased "
        "plan: Contain -> Eradicate -> Recover -> Post-incident. Each step names an "
        "owner role, a concrete command or change, a rollback, and a verification. "
        "Preserve forensic evidence before eradication. Propose only - flag every "
        "state-changing step for human approval. Map the work to NIST SP 800-61."
    )

    def __init__(self, llm=None) -> None:
        self.llm = llm or get_llm()

    def plan_for(self, cluster: list[Finding], target: ScanTarget) -> IncidentPlan:
        lead = max(cluster, key=lambda f: (SEVERITY_RANK[f.severity], f.confidence))
        # escalate priority when threat intel says it is actively exploited
        rank = SEVERITY_RANK[lead.severity]
        if lead.enrichment.get("kev") or lead.enrichment.get("exploited_in_wild"):
            rank = min(len(_PRIORITY) - 1 + 0, rank + 1)
        eff_sev = severity_from_rank(rank)
        priority, sla = _PRIORITY[eff_sev]

        steps = _steps_for(lead.category, lead.title)
        approvals = sorted({s.owner_role for s in steps if s.requires_human_approval})

        impact = {
            "asset_criticality": target.asset_criticality,
            "exposure": target.exposure,
            "blast_radius": self._blast_radius(cluster, target),
            "data_at_risk": self._data_at_risk(lead),
            "regulatory_exposure": self._regulatory(lead, target),
            "actively_exploited": bool(lead.enrichment.get("kev") or lead.enrichment.get("exploited_in_wild")),
        }

        comms = self.llm.incident_comms({
            "title": lead.title,
            "priority": priority,
            "sla": sla,
            "target": lead.target,
            "agent": lead.agent,
            "detected_at": lead.discovered_at,
            "description": lead.description,
            "first_step": steps[0].action if steps else "see plan",
        })

        return IncidentPlan(
            finding_ids=sorted({f.id for f in cluster}),
            title=f"IR plan: {lead.title}",
            priority=priority,
            sla=sla,
            nist_800_61_phase="Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity",
            steps=steps,
            impact=impact,
            required_approvals=approvals,
            evidence_preservation=list(_EVIDENCE_PRESERVATION),
            comms_draft=comms,
        )

    # `Agent.run` compatibility: context carries {"clusters": [[Finding, ...], ...]}
    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:
        clusters = context.get("clusters") or []
        plans = [self.plan_for(c, target) for c in clusters if c]
        # plans are returned via notes-free AgentResult; orchestrator reads context back
        context["_plans"] = plans
        return AgentResult(self.name, [], "ok", [f"generated {len(plans)} incident plan(s)"])

    # --- impact helpers ------------------------------------------

    @staticmethod
    def _blast_radius(cluster: list[Finding], target: ScanTarget) -> str:
        targets = sorted({f.target for f in cluster if f.target})
        scale = {"crown-jewel": "organization-wide", "high": "business-unit", "medium": "service", "low": "component"}
        return f"{scale.get(target.asset_criticality, 'service')}; artifacts: {', '.join(targets) or 'n/a'}"

    @staticmethod
    def _data_at_risk(f: Finding) -> str:
        c = (f.category + " " + f.title).lower()
        if "sqli" in c or "injection" in c or "t1190" in c:
            return "Application database contents (potential read/modify)"
        if "secret" in c or "cwe-798" in c or "t1110" in c:
            return "Credentials and anything they authorize"
        if "cve-" in c:
            return "Depends on the vulnerable component's role; assume code/data on the host"
        return "Undetermined - confirm during analysis"

    @staticmethod
    def _regulatory(f: Finding, target: ScanTarget) -> str:
        if target.exposure == "external" and target.asset_criticality in ("high", "crown-jewel"):
            return "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other)."
        return "Assess against applicable contractual and regulatory commitments."
