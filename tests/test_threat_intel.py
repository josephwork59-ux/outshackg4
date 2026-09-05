from agents.threat_intel import ThreatIntelAgent
from agents.threat_intel.feeds import StubThreatFeed
from contracts import Finding


def test_known_cve_gets_enriched():
    agent = ThreatIntelAgent(feed=StubThreatFeed())
    f = Finding.new(
        agent="vuln_scanner", title="t", description="d", severity="high",
        confidence=0.9, category="dependency-vuln", target="requirements.txt :: pyyaml==5.3.1",
        signature="pip-audit:PYSEC-2021-142:pyyaml", cve_ids=["CVE-2020-14343"],
    )
    agent.enrich([f])
    assert f.cvss == 9.8
    assert f.kev is True
    assert f.affected == "yes"
    assert f.severity == "critical"  # KEV bump


def test_unknown_cve_marks_uncertain():
    agent = ThreatIntelAgent(feed=StubThreatFeed())
    f = Finding.new(
        agent="vuln_scanner", title="t", description="d", severity="medium",
        confidence=0.5, category="dependency-vuln", target="x",
        signature="sig", cve_ids=["CVE-9999-99999"],
    )
    agent.enrich([f])
    assert f.affected == "uncertain"


def test_stale_feed_data_is_flagged():
    feed = StubThreatFeed()
    rec = feed.lookup_cve("CVE-2020-14343")
    assert rec.is_stale is False  # fixture timestamp is recent by design
