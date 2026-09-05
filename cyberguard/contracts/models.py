"""Typed models shared across the whole pipeline.

Pure standard library (dataclasses) so the core has zero runtime dependencies
and the same object flows unchanged from an agent, through the orchestrator,
into the report.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Ordered most severe -> least severe.
SEVERITIES = ("critical", "high", "medium", "low", "info")
# info=0 .. critical=4
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}


def severity_from_rank(rank: int) -> str:
    rank = max(0, min(len(SEVERITIES) - 1, int(rank)))
    return list(reversed(SEVERITIES))[rank]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    """A single security observation produced by an agent.

    `signature` is only used to derive a stable `id`; it is not serialized on
    its own. Two runs that see the same issue produce the same `id`, which is
    what lets the orchestrator deduplicate and correlate.
    """

    agent: str
    title: str
    description: str = ""
    severity: str = "info"
    confidence: float = 0.5
    category: str = ""  # CWE-79 / OWASP-A03 / ATT&CK T1110 / CVE-2020-14343 / control id
    target: str = ""  # file:line | image layer | log source | endpoint
    signature: str = ""
    evidence: list[str] = field(default_factory=list)  # redacted, always cited
    references: list[str] = field(default_factory=list)
    recommended_fix: str = ""
    requires_human_approval: bool = False
    discovered_at: str = field(default_factory=utcnow_iso)
    correlated_ids: list[str] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)  # filled by Threat Intel
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"
        self.confidence = round(max(0.0, min(1.0, float(self.confidence))), 3)
        if not self.id:
            self.id = self.make_id()

    def make_id(self) -> str:
        basis = "|".join([self.agent, self.target, self.signature or self.title])
        return "F-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("signature", None)
        return d


@dataclass
class IncidentStep:
    phase: str  # contain | eradicate | recover | post-incident
    action: str
    owner_role: str
    command_or_change: str = ""
    rollback: str = ""
    verification: str = ""
    requires_human_approval: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IncidentPlan:
    finding_ids: list[str]
    title: str
    priority: str  # P1..P4
    sla: str
    nist_800_61_phase: str
    steps: list[IncidentStep] = field(default_factory=list)
    impact: dict[str, Any] = field(default_factory=dict)
    required_approvals: list[str] = field(default_factory=list)
    evidence_preservation: list[str] = field(default_factory=list)
    comms_draft: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["steps"] = [s.to_dict() for s in self.steps]
        return d


@dataclass
class ControlAssessment:
    control_id: str
    title: str
    status: str  # Met | Partial | Not Met | N/A | Not Assessed
    rationale: str
    evidence_finding_ids: list[str] = field(default_factory=list)
    remediation: str = ""
    effort: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ComplianceReport:
    framework: str
    framework_version: str
    subset_note: str
    evaluated_controls: int
    coverage_pct: float
    assessments: list[ControlAssessment] = field(default_factory=list)
    failing_controls: list[str] = field(default_factory=list)
    remediation_backlog: list[dict] = field(default_factory=list)
    finding_control_matrix: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["assessments"] = [a.to_dict() for a in self.assessments]
        return d


@dataclass
class ScanTarget:
    name: str = "unnamed-target"
    log_sources: list[dict] = field(default_factory=list)  # {"path": str, "format": "syslog"|"nginx"|"auto"}
    repo_path: Optional[str] = None
    images: list[str] = field(default_factory=list)
    dockerfiles: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    openapi_spec: Optional[str] = None
    framework: str = "NIST_CSF"  # NIST_CSF | SOC2 | ISO27001
    asset_criticality: str = "medium"  # low | medium | high | crown-jewel
    exposure: str = "internal"  # internal | external
    allowlist: list[str] = field(default_factory=list)  # hosts permitted for ACTIVE testing
    allow_active: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "ScanTarget":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def from_json(cls, path: str) -> "ScanTarget":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def summary(self) -> dict:
        return {
            "name": self.name,
            "log_sources": [s.get("path") for s in self.log_sources],
            "repo_path": self.repo_path,
            "images": self.images,
            "dockerfiles": self.dockerfiles,
            "api_endpoints": self.api_endpoints,
            "framework": self.framework,
            "asset_criticality": self.asset_criticality,
            "exposure": self.exposure,
            "allow_active": self.allow_active,
        }


@dataclass
class AgentResult:
    """What every agent hands back to the orchestrator."""

    agent: str
    findings: list[Finding] = field(default_factory=list)
    status: str = "ok"  # ok | partial | failed
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    run_id: str
    started_at: str
    finished_at: str
    target_summary: dict
    findings: list[Finding] = field(default_factory=list)
    incident_plans: list[IncidentPlan] = field(default_factory=list)
    compliance: Optional[ComplianceReport] = None
    agent_status: dict[str, str] = field(default_factory=dict)
    executive_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target_summary": self.target_summary,
            "findings": [f.to_dict() for f in self.findings],
            "incident_plans": [p.to_dict() for p in self.incident_plans],
            "compliance": self.compliance.to_dict() if self.compliance else None,
            "agent_status": self.agent_status,
            "executive_summary": self.executive_summary,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
