"""Deduplicate and correlate findings across agents."""

from __future__ import annotations

import re
from collections import defaultdict

from contracts import Finding

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share an id (same agent + target + signature)."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        if f.id not in by_id:
            by_id[f.id] = f
            continue
        keep = by_id[f.id]
        for line in f.evidence:
            if line not in keep.evidence:
                keep.evidence.append(line)
        for ref in f.references:
            if ref and ref not in keep.references:
                keep.references.append(ref)
        for cid in f.correlated_ids:
            if cid not in keep.correlated_ids:
                keep.correlated_ids.append(cid)
        keep.confidence = max(keep.confidence, f.confidence)
    return list(by_id.values())


def _ips(f: Finding) -> set[str]:
    ips: set[str] = set()
    enr = f.enrichment or {}
    if enr.get("source_ip"):
        ips.add(enr["source_ip"])
    ips.update(enr.get("source_ips", []) or [])
    if enr.get("ioc_ip"):
        ips.add(enr["ioc_ip"])
    for line in f.evidence:
        ips.update(_IPV4_RE.findall(line))
    return ips


def _cves(f: Finding) -> set[str]:
    blob = " ".join([f.category, f.title, f.description, " ".join(f.references)])
    return {m.group(0).upper() for m in _CVE_RE.finditer(blob)}


def _link(a: Finding, b: Finding, reason: str) -> None:
    if b.id not in a.correlated_ids and b.id != a.id:
        a.correlated_ids.append(b.id)
        a.enrichment.setdefault("correlations", []).append({"with": b.id, "reason": reason})
    if a.id not in b.correlated_ids and a.id != b.id:
        b.correlated_ids.append(a.id)
        b.enrichment.setdefault("correlations", []).append({"with": a.id, "reason": reason})


def correlate(findings: list[Finding]) -> list[dict]:
    """Link related findings in place. Returns a list of correlation summaries."""
    summaries: list[dict] = []

    by_ip: dict[str, list[Finding]] = defaultdict(list)
    by_cve: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for ip in _ips(f):
            by_ip[ip].append(f)
        for cve in _cves(f):
            by_cve[cve].append(f)

    for ip, group in by_ip.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                _link(group[i], group[j], f"shared source IP {ip}")
        summaries.append({
            "type": "shared-ip",
            "key": ip,
            "finding_ids": sorted({f.id for f in group}),
            "note": f"{len(group)} findings involve {ip}",
        })

    for cve, group in by_cve.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                _link(group[i], group[j], f"same vulnerability {cve}")
        summaries.append({
            "type": "shared-cve",
            "key": cve,
            "finding_ids": sorted({f.id for f in group}),
            "note": f"{len(group)} findings concern {cve}",
        })

    return summaries


def clusters_for_ir(findings: list[Finding], min_conf: float = 0.7) -> list[list[Finding]]:
    """Group correlated findings; keep clusters that contain a high+ or confident finding."""
    index = {f.id: f for f in findings}
    seen: set[str] = set()
    clusters: list[list[Finding]] = []

    for f in findings:
        if f.id in seen:
            continue
        stack = [f.id]
        group: list[Finding] = []
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in index:
                continue
            seen.add(cur)
            node = index[cur]
            group.append(node)
            stack.extend(cid for cid in node.correlated_ids if cid not in seen)

        worthy = any(
            g.severity in ("critical", "high") or g.confidence >= min_conf
            for g in group
        )
        if worthy:
            clusters.append(sorted(group, key=lambda g: g.id))

    return clusters
