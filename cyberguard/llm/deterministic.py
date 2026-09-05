"""Offline, deterministic stand-in for a reasoning LLM.

Template-driven so `make demo` and the tests produce byte-stable output with no
network and no API key. Good enough to exercise the whole pipeline; swap in
`ClaudeLLM` for production-quality prose.
"""

from __future__ import annotations

import textwrap


class DeterministicLLM:
    name = "deterministic"

    def summarize_advisory(self, text: str) -> str:
        text = " ".join((text or "").split())
        if not text:
            return "No advisory text available."
        head = text[:240]
        return f"Advisory summary: {head}{'...' if len(text) > 240 else ''}"

    def correlation_narrative(self, bullet_points: list[str]) -> str:
        if not bullet_points:
            return "No correlations were established between findings."
        joined = "; ".join(bullet_points)
        return (
            "Correlation analysis links the following observations into a single "
            f"probable activity chain: {joined}."
        )

    def executive_summary(self, facts: dict) -> str:
        counts = facts.get("severity_counts", {})
        top = facts.get("top_findings", [])
        plans = facts.get("incident_plan_count", 0)
        cov = facts.get("compliance_coverage_pct")
        fw = facts.get("framework", "the selected framework")
        failing = facts.get("failing_control_count", 0)

        sev_line = ", ".join(
            f"{counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info")
        )
        cov_txt = f"{cov:.0f}%" if isinstance(cov, (int, float)) else "n/a"

        lines = [
            f"This scan produced {facts.get('finding_count', 0)} findings ({sev_line}). "
            f"{plans} incident response plan(s) were generated for confirmed or "
            "high-confidence issues.",
            "",
            "Highest-priority items:",
        ]
        lines += [f"  - {t}" for t in (top[:5] or ["(none)"])]
        lines += [
            "",
            f"Compliance: mapped against {fw}; estimated control coverage {cov_txt} "
            f"with {failing} control(s) currently failing or partial. All remediation is "
            "proposed only - no state-changing action was executed. Human review is required "
            "before acting on any plan step flagged for approval.",
        ]
        return "\n".join(lines)

    def incident_comms(self, facts: dict) -> str:
        return textwrap.dedent(
            f"""
            SECURITY NOTIFICATION (INTERNAL - DRAFT)

            Summary: {facts.get('title', 'Security issue detected')}
            Priority: {facts.get('priority', 'P3')}   SLA: {facts.get('sla', 'n/a')}
            Affected: {facts.get('target', 'see finding')}
            Detected by: {facts.get('agent', 'CyberGuard')} at {facts.get('detected_at', 'n/a')}

            What we know: {facts.get('description', 'n/a')}
            Immediate actions proposed: {facts.get('first_step', 'see incident plan')}

            This is an automated draft. Confirm details and obtain approval before
            executing any containment or eradication step.
            """
        ).strip()
