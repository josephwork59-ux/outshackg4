"""Supervisor logic: dedupe, correlate, and finalize severity/priority for
the merged findings set. This is deliberately deterministic (no LLM) so the
same inputs always produce the same final severities — the orchestrator's
job per spec is to "merge findings, dedupe, prioritize, report", not to
generate new judgments.
"""
from __future__ import annotations

from contracts import Finding, severity_weight

_ASSET_CRITICALITY_DEFAULT = 1.0  # multiplier; a real system would look this up per asset

_WEIGHT_TO_SEVERITY = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Findings share a stable id (agent, target, signature) — same id means
    same underlying issue, keep the first occurrence."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f
    return list(seen.values())


def correlate(findings: list[Finding]) -> list[Finding]:
    """Link findings that share a target or an overlapping IP/CVE mention so
    the Incident Response agent can build one plan for a cluster instead of
    N duplicate plans. Cheap heuristic, good enough for a demo-scale run."""
    by_target: dict[str, list[Finding]] = {}
    for f in findings:
        by_target.setdefault(f.target.split(":")[0], []).append(f)

    for group in by_target.values():
        if len(group) < 2:
            continue
        ids = [f.id for f in group]
        for f in group:
            f.correlated_ids = [i for i in ids if i != f.id]
    return findings


def finalize_severity(findings: list[Finding], asset_criticality: float = _ASSET_CRITICALITY_DEFAULT) -> list[Finding]:
    """final = base_severity_weight * exploit_maturity * asset_criticality * exposure
    then re-quantized back to a Severity label. Each multiplier defaults to 1.0
    (neutral) when the signal isn't available, so a finding's severity is
    never *downgraded* by missing enrichment — only upgraded by corroborating
    evidence (KEV, exploited_in_wild, correlation cluster size)."""
    for f in findings:
        base = severity_weight(f.severity)
        exploit_maturity = 1.0
        if f.kev or f.exploited_in_wild:
            exploit_maturity = 1.5
        elif f.epss is not None and f.epss >= 0.5:
            exploit_maturity = 1.3

        exposure = 1.0
        if len(f.correlated_ids) >= 2:
            exposure = 1.2  # part of a larger correlated cluster -> more exposure

        score = base * exploit_maturity * asset_criticality * exposure
        new_weight = min(5, max(1, round(score)))
        f.severity = _WEIGHT_TO_SEVERITY[new_weight]  # type: ignore[assignment]
    return findings


def merge_and_prioritize(*finding_lists: list[Finding]) -> list[Finding]:
    merged: list[Finding] = []
    for lst in finding_lists:
        merged.extend(lst)
    merged = dedupe(merged)
    merged = correlate(merged)
    merged = finalize_severity(merged)
    merged.sort(key=lambda f: (severity_weight(f.severity), f.confidence), reverse=True)
    return merged
