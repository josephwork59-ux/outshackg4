"""Render a ScanReport as JSON + Markdown + a console summary."""

from __future__ import annotations

import json
import os
from typing import Tuple

from contracts import ScanReport, SEVERITY_RANK

_SEV_ICON = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def _sev_counts(report: ScanReport) -> dict:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_markdown(report: ScanReport) -> str:
    counts = _sev_counts(report)
    out: list[str] = []
    ap = out.append

    ap(f"# CyberGuard Scan Report - `{report.run_id}`")
    ap("")
    ap(f"- **Target:** {report.target_summary.get('name')}")
    ap(f"- **Started:** {report.started_at}  •  **Finished:** {report.finished_at}")
    ap(f"- **Findings:** {len(report.findings)} "
       f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, "
       f"low {counts['low']}, info {counts['info']})")
    ap(f"- **Incident plans:** {len(report.incident_plans)}")
    if report.compliance:
        c = report.compliance
        ap(f"- **Compliance:** {c.framework} {c.framework_version} - coverage {c.coverage_pct}% - "
           f"{len(c.failing_controls)} failing/partial")
    ap("")
    ap("> All remediation below is **proposed only**. No state-changing action was executed.")
    ap("")

    ap("## Executive summary")
    ap("")
    ap(report.executive_summary or "_none_")
    ap("")

    ap("## Agent status")
    ap("")
    ap("| Agent | Status |")
    ap("| --- | --- |")
    for agent, st in report.agent_status.items():
        ap(f"| {agent} | {st} |")
    ap("")

    ap("## Findings")
    ap("")
    for f in sorted(report.findings, key=lambda x: (SEVERITY_RANK[x.severity], x.confidence), reverse=True):
        ap(f"### {_SEV_ICON[f.severity]} {f.title}")
        ap("")
        ap(f"- **id:** `{f.id}`  •  **agent:** {f.agent}  •  **severity:** {f.severity}  "
           f"•  **confidence:** {f.confidence:.2f}")
        ap(f"- **category:** {f.category or 'n/a'}  •  **target:** `{f.target or 'n/a'}`")
        if f.correlated_ids:
            ap(f"- **correlated with:** {', '.join('`' + c + '`' for c in f.correlated_ids)}")
        adj = f.enrichment.get("severity_adjustment")
        if adj:
            ap(f"- **severity adjusted:** {adj.get('from')} -> {adj.get('to')} ({adj.get('reason')})")
        if f.description:
            ap(f"- {f.description}")
        if f.evidence:
            ap("- **evidence:**")
            for line in f.evidence[:8]:
                ap(f"  - `{line}`")
        if f.enrichment.get("threat_intel"):
            for cve, ti in f.enrichment["threat_intel"].items():
                ap(f"- **threat intel {cve}:** affected={ti.get('affected')} "
                   f"cvss={ti.get('cvss')} epss={ti.get('epss')} kev={ti.get('kev')} "
                   f"fixed={ti.get('fixed_version')}")
        if f.enrichment.get("ioc"):
            for ip, ioc in f.enrichment["ioc"].items():
                ap(f"- **IOC {ip}:** {ioc.get('category')} (campaign {ioc.get('campaign')})")
        if f.recommended_fix:
            ap(f"- **recommended fix:** {f.recommended_fix}")
        if f.references:
            ap(f"- **refs:** {', '.join(f.references[:5])}")
        ap("")

    ap("## Incident response plans")
    ap("")
    if not report.incident_plans:
        ap("_No plans generated (no confirmed or high-confidence clusters)._")
        ap("")
    for p in report.incident_plans:
        ap(f"### {p.title}")
        ap("")
        ap(f"- **priority:** {p.priority}  •  **SLA:** {p.sla}")
        ap(f"- **findings:** {', '.join('`' + i + '`' for i in p.finding_ids)}")
        ap(f"- **NIST SP 800-61:** {p.nist_800_61_phase}")
        ap(f"- **impact:** {json.dumps(p.impact)}")
        ap(f"- **required approvals:** {', '.join(p.required_approvals) or 'none'}")
        ap("- **evidence preservation:**")
        for e in p.evidence_preservation:
            ap(f"  - {e}")
        ap("- **steps:**")
        for i, s in enumerate(p.steps, 1):
            flag = " _(needs human approval)_" if s.requires_human_approval else ""
            ap(f"  {i}. **[{s.phase}]** {s.action} - owner: {s.owner_role}{flag}")
            if s.command_or_change:
                ap(f"     - change: `{s.command_or_change}`")
            if s.rollback and s.rollback != "n/a":
                ap(f"     - rollback: {s.rollback}")
            if s.verification:
                ap(f"     - verify: {s.verification}")
        ap("")
        ap("<details><summary>Comms draft</summary>")
        ap("")
        ap("```")
        ap(p.comms_draft)
        ap("```")
        ap("")
        ap("</details>")
        ap("")

    if report.compliance:
        c = report.compliance
        ap(f"## Compliance - {c.framework} {c.framework_version}")
        ap("")
        ap(f"_{c.subset_note}_")
        ap("")
        ap(f"- **evaluated controls:** {c.evaluated_controls}")
        ap(f"- **coverage:** {c.coverage_pct}%")
        ap(f"- **failing / partial:** {', '.join(c.failing_controls) or 'none'}")
        ap("")
        ap("| Control | Title | Status | Evidence | Effort |")
        ap("| --- | --- | --- | --- | --- |")
        for a in c.assessments:
            ev = ", ".join(a.evidence_finding_ids) if a.evidence_finding_ids else "-"
            ap(f"| {a.control_id} | {a.title} | {a.status} | {ev} | {a.effort or '-'} |")
        ap("")
        if c.remediation_backlog:
            ap("### Remediation backlog (worst first)")
            ap("")
            for b in c.remediation_backlog:
                ap(f"- **{b['control_id']}** ({b['status']}, worst {b['worst_severity']}, {b['effort']}): "
                   f"{b['remediation']}")
            ap("")
        ap("### Finding -> control matrix")
        ap("")
        if c.finding_control_matrix:
            for fid, ctrls in c.finding_control_matrix.items():
                ap(f"- `{fid}` -> {', '.join(ctrls)}")
        else:
            ap("_no mappings_")
        ap("")

    return "\n".join(out)


def render_console(report: ScanReport) -> str:
    counts = _sev_counts(report)
    lines = [
        "=" * 68,
        f" CyberGuard  {report.run_id}",
        "=" * 68,
        f" findings : {len(report.findings)}  "
        f"(C{counts['critical']} H{counts['high']} M{counts['medium']} L{counts['low']} I{counts['info']})",
        f" plans    : {len(report.incident_plans)}",
    ]
    if report.compliance:
        c = report.compliance
        lines.append(f" compliance: {c.framework} {c.framework_version}  "
                     f"coverage {c.coverage_pct}%  failing {len(c.failing_controls)}")
    lines.append(" agents   : " + ", ".join(f"{k}={v}" for k, v in report.agent_status.items()))
    lines.append("-" * 68)
    for f in sorted(report.findings, key=lambda x: (SEVERITY_RANK[x.severity], x.confidence), reverse=True)[:12]:
        lines.append(f" {_SEV_ICON[f.severity]} {f.title[:88]}")
    if len(report.findings) > 12:
        lines.append(f" ... and {len(report.findings) - 12} more")
    lines.append("=" * 68)
    lines.append(" NOTE: all remediation is proposed only; nothing was executed.")
    return "\n".join(lines)


def build_report_files(report: ScanReport, out_dir: str) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"{report.run_id}.json")
    md_path = os.path.join(out_dir, f"{report.run_id}.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(report.to_json())
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    return json_path, md_path
