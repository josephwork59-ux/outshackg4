"""Threat-intel feed interfaces.

Per project decision: local code/dependency scanners are real (semgrep,
bandit, pip-audit, trivy) but external threat-intel feeds (NVD, OSV,
GitHub Advisory, CISA KEV) are **stubbed** behind a documented interface, so
the demo runs deterministically offline / without API keys. Swap
`StubThreatFeed` for a real implementation of `ThreatFeed` to go live —
no other code changes needed.
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

STALENESS_THRESHOLD_DAYS = 7
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "threat_feed_fixtures.json"


@dataclass
class CveRecord:
    cve_id: str
    summary: str
    cvss: Optional[float]
    epss: Optional[float]
    kev: bool
    exploited_in_wild: bool
    fixed_version: Optional[str]
    source_url: str
    feed_timestamp: float
    found: bool = True

    @property
    def is_stale(self) -> bool:
        age_days = (time.time() - self.feed_timestamp) / 86400
        return age_days > STALENESS_THRESHOLD_DAYS


@dataclass
class IocRecord:
    indicator: str
    indicator_type: str
    malicious: bool
    campaign: Optional[str]
    confidence: float
    source_url: str
    feed_timestamp: float
    found: bool = True


class ThreatFeed(ABC):
    """Documented interface every threat-intel backend must implement."""

    @abstractmethod
    def lookup_cve(self, cve_id: str) -> CveRecord: ...

    @abstractmethod
    def check_kev(self, cve_id: str) -> bool: ...

    @abstractmethod
    def enrich_ioc(self, indicator: str, indicator_type: str = "ip") -> IocRecord: ...


class StubThreatFeed(ThreatFeed):
    """Deterministic canned responses loaded from a fixtures file, so
    `make demo` produces the same enrichment every run without network
    access. Any CVE/IOC not present in the fixture file returns a
    `found=False` record rather than fabricating data — the agent surfaces
    that as 'affected: uncertain'."""

    def __init__(self, fixtures_path: Path = FIXTURE_PATH):
        self._data = json.loads(fixtures_path.read_text()) if fixtures_path.exists() else {
            "cves": {}, "iocs": {}, "kev": [],
        }

    def lookup_cve(self, cve_id: str) -> CveRecord:
        rec = self._data.get("cves", {}).get(cve_id)
        if not rec:
            return CveRecord(
                cve_id=cve_id, summary="No fixture data for this CVE.",
                cvss=None, epss=None, kev=cve_id in self._data.get("kev", []),
                exploited_in_wild=False, fixed_version=None,
                source_url="stub://threat-feed/not-found",
                feed_timestamp=time.time(), found=False,
            )
        return CveRecord(
            cve_id=cve_id, summary=rec["summary"], cvss=rec.get("cvss"),
            epss=rec.get("epss"), kev=cve_id in self._data.get("kev", []),
            exploited_in_wild=rec.get("exploited_in_wild", False),
            fixed_version=rec.get("fixed_version"),
            source_url=rec.get("source_url", "stub://threat-feed"),
            feed_timestamp=rec.get("feed_timestamp", time.time()),
        )

    def check_kev(self, cve_id: str) -> bool:
        return cve_id in self._data.get("kev", [])

    def enrich_ioc(self, indicator: str, indicator_type: str = "ip") -> IocRecord:
        rec = self._data.get("iocs", {}).get(indicator)
        if not rec:
            return IocRecord(
                indicator=indicator, indicator_type=indicator_type, malicious=False,
                campaign=None, confidence=0.0, source_url="stub://threat-feed/not-found",
                feed_timestamp=time.time(), found=False,
            )
        return IocRecord(
            indicator=indicator, indicator_type=indicator_type,
            malicious=rec.get("malicious", False), campaign=rec.get("campaign"),
            confidence=rec.get("confidence", 0.5),
            source_url=rec.get("source_url", "stub://threat-feed"),
            feed_timestamp=rec.get("feed_timestamp", time.time()),
        )


_default_feed: ThreatFeed | None = None


def get_default_feed() -> ThreatFeed:
    global _default_feed
    if _default_feed is None:
        _default_feed = StubThreatFeed()
    return _default_feed
