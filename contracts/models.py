"""Shared data contracts used by every agent, the orchestrator, and the report
builder. These are the *only* objects that cross agent boundaries — every
agent must produce and consume these shapes so the orchestrator can merge,
dedupe, and correlate findings without agent-specific glue code.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def severity_weight(sev: Severity) -> int:
    return _SEVERITY_WEIGHT.get(sev, 0)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def stable_finding_id(agent: str, target: str, signature: str) -> str:
    """Deterministic id so the same underlying issue reported twice (e.g. across
    re-runs) dedupes to the same Finding id instead of piling up duplicates."""
    raw = f"{agent}|{target}|{signature}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


class AgentStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class Finding(BaseModel):
    id: str
    agent: str
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: str  # CWE / OWASP / ATT&CK / control id
    target: str  # file:line | image layer | log source | endpoint
    evidence: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    recommended_fix: str = ""
    requires_human_approval: bool = True
    discovered_at: datetime = Field(default_factory=now_utc)
    correlated_ids: list[str] = Field(default_factory=list)

    # Enrichment fields populated by the Threat Intelligence agent; left
    # unset for findings that never pass through that agent.
    cve_ids: list[str] = Field(default_factory=list)
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: Optional[bool] = None
    exploited_in_wild: Optional[bool] = None
    affected: Optional[Literal["yes", "no", "uncertain"]] = None

    @classmethod
    def new(
        cls,
        *,
        agent: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        category: str,
        target: str,
        signature: str,
        evidence: list[str] | None = None,
        references: list[str] | None = None,
        recommended_fix: str = "",
        requires_human_approval: bool = True,
        **kwargs,
    ) -> "Finding":
        return cls(
            id=stable_finding_id(agent, target, signature),
            agent=agent,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            category=category,
            target=target,
            evidence=evidence or [],
            references=references or [],
            recommended_fix=recommended_fix,
            requires_human_approval=requires_human_approval,
            **kwargs,
        )


class IncidentPhase(str, Enum):
    CONTAIN = "contain"
    ERADICATE = "eradicate"
    RECOVER = "recover"
    POST_INCIDENT = "post_incident"


class IncidentStep(BaseModel):
    phase: IncidentPhase
    order: int
    description: str
    owner_role: str
    command_or_change: str
    rollback: str
    verification: str
    requires_human_approval: bool = True


class IncidentPlan(BaseModel):
    id: str
    finding_id: str
    finding_ids: list[str] = Field(default_factory=list)  # for correlated clusters
    priority: Literal["P1", "P2", "P3", "P4"]
    sla_target: str
    steps: list[IncidentStep]
    required_approvals: list[str] = Field(default_factory=list)
    evidence_preservation_checklist: list[str] = Field(default_factory=list)
    impact_summary: str = ""
    comms_draft: str = ""
    playbook_reference: str = "NIST SP 800-61"
    created_at: datetime = Field(default_factory=now_utc)


class ControlAssessment(BaseModel):
    control_id: str
    control_name: str
    status: Literal["Met", "Partial", "Not Met", "N/A"]
    rationale: str
    evidence_finding_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    effort_estimate: str = ""


class ComplianceReport(BaseModel):
    framework: str
    framework_version: str
    control_subset_note: str
    coverage_percent: float
    assessments: list[ControlAssessment]

    @property
    def failing_controls(self) -> list[ControlAssessment]:
        return [a for a in self.assessments if a.status in ("Not Met", "Partial")]


class ScanTarget(BaseModel):
    log_sources: list[str] = Field(default_factory=list)
    repo_path: Optional[str] = None
    image_names: list[str] = Field(default_factory=list)
    openapi_spec: Optional[str] = None
    api_base_url: Optional[str] = None
    allow_active: bool = False
    target_allowlist: list[str] = Field(default_factory=list)
    compliance_framework: str = "NIST CSF 2.0"


class ScanReport(BaseModel):
    run_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    target_summary: str
    findings: list[Finding] = Field(default_factory=list)
    incident_plans: list[IncidentPlan] = Field(default_factory=list)
    compliance: Optional[ComplianceReport] = None
    agent_status: dict[str, str] = Field(default_factory=dict)
    executive_summary: str = ""
