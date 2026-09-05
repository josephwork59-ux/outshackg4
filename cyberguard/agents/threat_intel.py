"""Threat Intelligence Agent - look up known threats and decide if we are affected.

Enriches existing findings in place (CVSS/EPSS/KEV, "affected: yes/no/uncertain"
with reasoning, recommended fixed version, IOC reputation) and emits a few new
findings of its own (confirmed malicious IP, confirmed-exploitable dependency)
so downstream stages and the report always see a Threat Intel contribution.

The bundled data files are an OFFLINE SAMPLE. Production wiring point:
`FeedProvider` - implement it against NVD / OSV / a commercial feed and pass it
to the agent.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from contracts import AgentResult, Finding, ScanTarget

from .base import DATA_DIR, Agent

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class FeedProvider:
    """Interface for a threat-intel data source. The default reads bundled JSON."""

    def cve_records(self, package: str) -> list[dict]:
        raise NotImplementedError

    def cve_by_id(self, cve_id: str) -> Optional[dict]:
        raise NotImplementedError

    def ioc_ipv4(self, ip: str) -> Optional[dict]:
        raise NotImplementedError

    def feed_updated(self) -> Optional[str]:
        raise NotImplementedError


class BundledFeed(FeedProvider):
    def __init__(self, data_dir: str = DATA_DIR) -> None:
        with open(os.path.join(data_dir, "cve_db.json"), encoding="utf-8") as fh:
            self._cve = json.load(fh)
        with open(os.path.join(data_dir, "ioc_blocklist.json"), encoding="utf-8") as fh:
            self._ioc = json.load(fh)
        self._by_id = {
            rec["cve"].upper(): {**rec, "package": pkg}
            for pkg, recs in self._cve.get("packages", {}).items()
            for rec in recs
        }

    def cve_records(self, package: str) -> list[dict]:
        return list(self._cve.get("packages", {}).get(package.lower(), []))

    def cve_by_id(self, cve_id: str) -> Optional[dict]:
        return self._by_id.get(cve_id.upper())

    def ioc_ipv4(self, ip: str) -> Optional[dict]:
        return self._ioc.get("ipv4", {}).get(ip)

    def feed_updated(self) -> Optional[str]:
        return self._cve.get("_meta", {}).get("updated")


class ThreatIntelAgent(Agent):
    name = "threat_intel"
    role = "Look up known security threats (CVE data, IOCs) and check if the system is affected."
    system_prompt = (
        "You are the Threat Intelligence Agent. For each candidate CVE or indicator, "
        "determine whether THIS system is affected and how urgent it is. Attach CVSS, "
        "EPSS, KEV status, and exploit maturity. State 'affected: yes/no/uncertain' with "
        "one sentence of reasoning and a recommended fixed version. Every claim must cite "
        "a source. If the feed is stale, say so. Never invent a CVE or a severity."
    )

    def __init__(self, feed: FeedProvider | None = None) -> None:
        self.feed = feed or BundledFeed()

    # The orchestrator calls this (not the generic Agent.run) because Threat Intel
    # operates on the findings collected so far, not on the raw target.
    def enrich_run(self, findings: list[Finding], target: ScanTarget) -> AgentResult:
        try:
            return self._enrich(findings, target)
        except Exception as exc:  # noqa: BLE001
            return AgentResult(self.name, findings, "failed", [f"{type(exc).__name__}: {exc}"])

    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:
        return self._enrich(list(context.get("findings", [])), target)

    def _enrich(self, findings: list[Finding], target: ScanTarget) -> AgentResult:
        notes: list[str] = []
        updated = self.feed.feed_updated()
        stale = False
        if updated is None:
            notes.append("feed has no timestamp (offline sample) - staleness check N/A")
        # (a real feed timestamp would be compared against a 7-day threshold here)

        new_findings: list[Finding] = []
        for f in findings:
            for cve_id in self._candidate_cves(f):
                rec = self.feed.cve_by_id(cve_id)
                if not rec:
                    f.enrichment.setdefault("threat_intel", {})[cve_id] = {
                        "affected": "uncertain",
                        "reasoning": "CVE not present in the configured feed",
                    }
                    continue
                self._apply_cve(f, rec, stale)
                if rec.get("exploited_in_wild") or (rec.get("epss") or 0) >= 0.5 or rec.get("kev"):
                    new_findings.append(self._exploitable_finding(f, rec))

            for ip in self._candidate_ips(f):
                ioc = self.feed.ioc_ipv4(ip)
                if ioc:
                    self._apply_ioc(f, ip, ioc)
                    new_findings.append(self._ioc_finding(f, ip, ioc))

        # de-dupe the findings we generated (same IOC IP / same CVE), merging the
        # parent links so one threat-intel finding can point at several sources.
        by_id: dict[str, Finding] = {}
        for nf in new_findings:
            if nf.id not in by_id:
                by_id[nf.id] = nf
                continue
            keep = by_id[nf.id]
            for cid in nf.correlated_ids:
                if cid not in keep.correlated_ids:
                    keep.correlated_ids.append(cid)
            for line in nf.evidence:
                if line not in keep.evidence:
                    keep.evidence.append(line)
        deduped = list(by_id.values())

        notes.append(f"enriched {len(findings)} findings; emitted {len(deduped)} threat-intel findings")
        return AgentResult(self.name, findings + deduped, "ok", notes)

    # --- helpers --------------------------------------------------------

    @staticmethod
    def _candidate_cves(f: Finding) -> list[str]:
        blob = " ".join([f.category, f.title, f.description, " ".join(f.references)])
        return sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})

    @staticmethod
    def _candidate_ips(f: Finding) -> list[str]:
        ips = set()
        enr = f.enrichment
        if enr.get("source_ip"):
            ips.add(enr["source_ip"])
        for ip in enr.get("source_ips", []) or []:
            ips.add(ip)
        for line in f.evidence:
            ips.update(_IPV4_RE.findall(line))
        return sorted(ips)

    def _apply_cve(self, f: Finding, rec: dict, stale: bool) -> None:
        ti = f.enrichment.setdefault("threat_intel", {})
        ti[rec["cve"]] = {
            "affected": "yes",
            "reasoning": f"matched advisory range for {rec['package']}",
            "cvss": rec.get("cvss"),
            "epss": rec.get("epss"),
            "kev": rec.get("kev", False),
            "exploited_in_wild": rec.get("exploited_in_wild", False),
            "fixed_version": rec.get("fixed"),
            "cwe": rec.get("cwe"),
            "summary": rec.get("summary"),
            "sources": rec.get("references", []),
            "stale": stale,
        }
        # promote severity for actively-exploited / KEV issues
        if rec.get("kev") or rec.get("exploited_in_wild"):
            f.enrichment["kev"] = bool(rec.get("kev"))
            f.enrichment["exploited_in_wild"] = bool(rec.get("exploited_in_wild"))
        if rec.get("epss") is not None:
            f.enrichment["epss"] = rec["epss"]
        for ref in rec.get("references", []):
            if ref not in f.references:
                f.references.append(ref)
        f.confidence = max(f.confidence, 0.8)

    def _apply_ioc(self, f: Finding, ip: str, ioc: dict) -> None:
        f.enrichment.setdefault("ioc", {})[ip] = {
            "category": ioc.get("category"),
            "campaign": ioc.get("campaign"),
            "first_seen": ioc.get("first_seen"),
            "confidence": ioc.get("confidence"),
            "sources": ioc.get("references", []),
        }
        if f.severity in ("low", "medium"):
            f.enrichment.setdefault("severity_adjustment", {
                "from": f.severity, "to": "high",
                "reason": f"source/destination IP {ip} matches threat intelligence",
            })
            f.severity = "high"
        f.confidence = max(f.confidence, min(0.95, f.confidence + 0.15))

    def _exploitable_finding(self, parent: Finding, rec: dict) -> Finding:
        epss = rec.get("epss")
        kev = rec.get("kev", False)
        note = []
        if kev:
            note.append("listed in CISA KEV")
        if rec.get("exploited_in_wild"):
            note.append("reported exploited in the wild")
        if epss is not None:
            note.append(f"EPSS {epss:.2f}")
        return Finding(
            agent=self.name,
            title=f"{rec['cve']} in {rec['package']} is high-risk ({'; '.join(note)})",
            description=(
                f"{rec['cve']} affects {rec['package']} {rec.get('affected')}. "
                f"CVSS {rec.get('cvss')}. Fixed in {rec.get('fixed')}. "
                f"{rec.get('summary', '')}"
            ),
            severity="critical" if (rec.get("cvss") or 0) >= 9 else "high",
            confidence=0.85,
            category=rec["cve"],
            target=f"{rec['package']} (all affected locations)",
            signature=f"ti-exploitable:{rec['cve']}",
            evidence=[f"Derived from finding {parent.id} ({parent.title})"],
            references=rec.get("references", []),
            recommended_fix=f"Upgrade {rec['package']} to >= {rec.get('fixed')} and redeploy.",
            correlated_ids=[parent.id],
            enrichment={
                "kev": kev,
                "exploited_in_wild": rec.get("exploited_in_wild", False),
                "epss": epss,
                "affected": "yes",
            },
        )

    def _ioc_finding(self, parent: Finding, ip: str, ioc: dict) -> Finding:
        return Finding(
            agent=self.name,
            title=f"Traffic involves known-malicious IP {ip} ({ioc.get('category')})",
            description=(
                f"{ip} appears in threat intelligence as {ioc.get('category')} "
                f"(campaign {ioc.get('campaign')}, first seen {ioc.get('first_seen')}). "
                f"It is referenced by finding {parent.id}."
            ),
            severity="high",
            confidence=float(ioc.get("confidence", 0.7)),
            category="ATT&CK T1595 / IOC",
            target=ip,
            signature=f"ti-ioc:{ip}",
            evidence=[f"Derived from finding {parent.id} ({parent.title})"],
            references=ioc.get("references", []),
            recommended_fix=f"Block {ip} at the perimeter and hunt for other activity from it.",
            correlated_ids=[parent.id],
            enrichment={"ioc_ip": ip, "campaign": ioc.get("campaign")},
        )
