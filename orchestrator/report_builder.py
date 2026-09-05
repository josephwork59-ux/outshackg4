from __future__ import annotations

from contracts import ScanReport
from tools.llm_client import LLMClient, get_llm_client


def build_executive_summary(report: ScanReport, llm: LLMClient | None = None) -> str:
    llm = llm or get_llm_client()
    sev_counts: dict[str, int] = {}
    for f in report.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    compliance_line = (
        f"Compliance coverage: {report.compliance.coverage_percent}% of evaluated "
        f"{report.compliance.framework} {report.compliance.framework_version} controls met."
        if report.compliance else "No compliance assessment run."
    )
    prompt = (
        f"Run {report.run_id} against {report.target_summary}.\n"
        f"Findings by severity: {sev_counts}. Total: {len(report.findings)}.\n"
        f"Incident plans generated: {len(report.incident_plans)}.\n"
        f"{compliance_line}\n"
        f"Agent status: {report.agent_status}.\n\n"
        "Write a plain-English executive summary in under 200 words for a "
        "non-technical stakeholder. State the most urgent issue, whether the "
        "environment is currently exposed, and what happens next. Do not "
        "invent numbers beyond what is given."
    )
    return llm.complete(
        system="You are a CISO writing a 1-paragraph executive summary of a security scan. "
               "Be concise, factual, and avoid jargon.",
        prompt=prompt, max_tokens=350,
    )


def to_markdown(report: ScanReport) -> str:
    lines = [
        f"# Security Scan Report — {report.run_id}",
        "",
        f"**Target:** {report.target_summary}  ",
        f"**Started:** {report.started_at}  ",
        f"**Finished:** {report.finished_at}  ",
        "",
        "## Executive Summary",
        "",
        report.executive_summary or "(none)",
        "",
        "## Agent Status",
        "",
    ]
    for agent, status in report.agent_status.items():
        lines.append(f"- **{agent}**: {status}")

    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("No findings.")
    for f in sorted(report.findings, key=lambda x: x.severity):
        lines += [
            f"### [{f.severity.upper()}] {f.title}",
            "",
            f"- **id:** `{f.id}`  **agent:** {f.agent}  **category:** {f.category}  "
            f"**confidence:** {f.confidence:.2f}",
            f"- **target:** `{f.target}`",
            f"- **description:** {f.description}",
            f"- **recommended fix:** {f.recommended_fix}",
            f"- **requires human approval:** {f.requires_human_approval}",
        ]
        if f.cve_ids:
            lines.append(f"- **CVE(s):** {', '.join(f.cve_ids)}  CVSS: {f.cvss}  EPSS: {f.epss}  KEV: {f.kev}")
        if f.evidence:
            lines.append("- **evidence:**")
            for e in f.evidence:
                lines.append(f"  - `{e}`")
        if f.references:
            lines.append(f"- **references:** {', '.join(f.references)}")
        lines.append("")

    lines += ["## Incident Plans", ""]
    if not report.incident_plans:
        lines.append("No incident plans generated this run.")
    for p in report.incident_plans:
        lines += [
            f"### Plan for finding `{p.finding_id}` — Priority {p.priority} (SLA {p.sla_target})",
            "",
            f"**Impact:** {p.impact_summary}",
            "",
        ]
        for s in p.steps:
            lines += [
                f"- **[{s.phase.value.upper()}] step {s.order}**: {s.description}",
                f"  - owner: {s.owner_role} | action: {s.command_or_change}",
                f"  - rollback: {s.rollback} | verify: {s.verification}",
                f"  - requires human approval: {s.requires_human_approval}",
            ]
        lines.append("")

    if report.compliance:
        c = report.compliance
        lines += [
            "## Compliance",
            "",
            f"Framework: {c.framework} {c.framework_version} — {c.control_subset_note}",
            f"Coverage: {c.coverage_percent}%",
            "",
            "| Control | Name | Status | Rationale |",
            "|---|---|---|---|",
        ]
        for a in c.assessments:
            lines.append(f"| {a.control_id} | {a.control_name} | {a.status} | {a.rationale} |")

    return "\n".join(lines)


def to_console_summary(report: ScanReport) -> str:
    sev_counts: dict[str, int] = {}
    for f in report.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    lines = [
        "=" * 60,
        f"SCAN REPORT  run_id={report.run_id}",
        f"target: {report.target_summary}",
        f"agent status: {report.agent_status}",
        f"findings: {len(report.findings)}  {sev_counts}",
        f"incident plans: {len(report.incident_plans)}",
    ]
    if report.compliance:
        lines.append(
            f"compliance ({report.compliance.framework} {report.compliance.framework_version}): "
            f"{report.compliance.coverage_percent}% coverage, "
            f"{len(report.compliance.failing_controls)} failing control(s)"
        )
    lines.append("-" * 60)
    lines.append(report.executive_summary)
    lines.append("=" * 60)
    return "\n".join(lines)
