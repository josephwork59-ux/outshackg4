"""Final severity / priority scoring.

Starting from the agent's base severity:

  exploit maturity (can escalate across the high->critical line):
    + 2  if KEV or exploited-in-wild
    + 1  if EPSS >= 0.5

  business context (a single-level nudge for exposed, high-value assets - it can
  lift a low/medium, but it never manufactures a 'critical' on its own; only
  demonstrated exploitation or exploit maturity does that):
    + 1  if the asset is externally exposed AND (high or crown-jewel), applied
         only while the running rank is still below 'high'

  confidence:
    - 1  if confidence < 0.4

The result is clamped back into the five-level scale. Any change is recorded in
`enrichment.severity_adjustment` for auditability.
"""

from __future__ import annotations

from contracts import Finding, ScanTarget, SEVERITY_RANK, severity_from_rank


def finalize(finding: Finding, target: ScanTarget) -> None:
    rank = SEVERITY_RANK[finding.severity]
    enr = finding.enrichment or {}

    if enr.get("kev") or enr.get("exploited_in_wild"):
        rank += 2
    epss = enr.get("epss")
    if isinstance(epss, (int, float)) and epss >= 0.5:
        rank += 1

    high_value = target.asset_criticality in ("high", "crown-jewel")
    if target.exposure == "external" and high_value and rank < SEVERITY_RANK["high"]:
        rank += 1

    if finding.confidence < 0.4:
        rank -= 1
    if finding.correlated_ids:
        finding.confidence = min(1.0, round(finding.confidence + 0.1, 3))

    new_sev = severity_from_rank(rank)
    if new_sev != finding.severity:
        prior = finding.enrichment.get("severity_adjustment") or {}
        finding.enrichment["severity_adjustment"] = {
            "from": prior.get("from", finding.severity),
            "to": new_sev,
            "reason": "; ".join(
                filter(None, [
                    prior.get("reason"),
                    "context: exploit maturity / external exposure / asset criticality / confidence",
                ])
            ),
        }
        finding.severity = new_sev
