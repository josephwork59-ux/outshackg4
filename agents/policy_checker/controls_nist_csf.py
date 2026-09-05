"""A representative subset of NIST CSF 2.0 (Cybersecurity Framework) controls,
bundled so the demo runs with zero external dependency. This is explicitly
NOT the full catalog — see `CONTROL_SUBSET_NOTE`.

Each control declares which Finding categories/agents count as relevant
evidence, so `map_finding_to_control` stays deterministic and auditable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

FRAMEWORK_NAME = "NIST CSF"
FRAMEWORK_VERSION = "2.0"
CONTROL_SUBSET_NOTE = (
    "Representative subset of 10 controls across the 6 CSF 2.0 functions "
    "(Govern, Identify, Protect, Detect, Respond, Recover) — not the full catalog."
)


@dataclass
class Control:
    control_id: str
    name: str
    function: str
    description: str
    # Match rules: a Finding is relevant evidence if its agent is in
    # `relevant_agents` AND (no category filter, or its category/title
    # matches one of `category_keywords`).
    relevant_agents: list[str] = field(default_factory=list)
    category_keywords: list[str] = field(default_factory=list)
    # If true, zero relevant findings = "Met" (absence of the bad thing is
    # the evidence). Otherwise zero relevant findings = "N/A".
    pass_on_no_findings: bool = False


CONTROLS: list[Control] = [
    Control(
        "GV.RM-01", "Risk management strategy is established", "Govern",
        "Organizational risk management objectives are established and agreed to by stakeholders.",
        relevant_agents=["policy_checker"],
        pass_on_no_findings=False,
    ),
    Control(
        "ID.AM-02", "Software platforms and applications are inventoried", "Identify",
        "Inventory of software/dependencies exists (evidenced by dependency scan coverage).",
        relevant_agents=["vuln_scanner"], category_keywords=["dependency-vuln"],
        pass_on_no_findings=False,
    ),
    Control(
        "ID.RA-01", "Vulnerabilities are identified and documented", "Identify",
        "Vulnerabilities in assets are identified and recorded.",
        relevant_agents=["vuln_scanner"],
        pass_on_no_findings=True,
    ),
    Control(
        "PR.AA-01", "Identities and credentials are managed", "Protect",
        "Credentials are protected; no hardcoded secrets in code or containers.",
        relevant_agents=["vuln_scanner"], category_keywords=["CWE-798", "secret"],
        pass_on_no_findings=True,
    ),
    Control(
        "PR.PS-02", "Software is maintained, replaced, and removed per risk", "Protect",
        "Known-vulnerable dependencies and container images are patched or replaced.",
        relevant_agents=["vuln_scanner"],
        category_keywords=["dependency-vuln", "container-image-vuln"],
        pass_on_no_findings=True,
    ),
    Control(
        "PR.IR-01", "Networks and environments are protected", "Protect",
        "Container/infra configuration follows hardening baselines (non-root, pinned images).",
        relevant_agents=["vuln_scanner"], category_keywords=["CIS-Docker-Benchmark"],
        pass_on_no_findings=True,
    ),
    Control(
        "DE.CM-01", "Networks and network services are monitored", "Detect",
        "Log monitoring detects anomalous network/auth activity.",
        relevant_agents=["log_monitor"],
        pass_on_no_findings=False,
    ),
    Control(
        "DE.AE-02", "Potentially adverse events are analyzed", "Detect",
        "Detected events are enriched with threat intelligence context.",
        relevant_agents=["threat_intel", "log_monitor"],
        pass_on_no_findings=False,
    ),
    Control(
        "RS.MA-01", "Incident response plan is executed", "Respond",
        "Confirmed high-severity findings have a documented, phased incident response plan.",
        relevant_agents=["incident_response"],
        pass_on_no_findings=True,
    ),
    Control(
        "RC.RP-01", "Recovery plan is executed", "Recover",
        "Incident plans include a Recover phase with verification steps before closure.",
        relevant_agents=["incident_response"],
        pass_on_no_findings=True,
    ),
]


def load_controls(framework: str = "NIST CSF 2.0") -> list[Control]:
    if framework.upper().replace(" ", "") not in ("NISTCSF2.0", "NISTCSF"):
        raise ValueError(f"Unsupported framework in this bundled subset: {framework}")
    return CONTROLS
