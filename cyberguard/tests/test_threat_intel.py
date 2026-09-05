from agents import ThreatIntelAgent
from agents.threat_intel import BundledFeed
from contracts import Finding, ScanTarget


def test_enriches_cve_finding_with_cvss_and_fix():
    f = Finding(agent="vuln_scanner", title="Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343)",
               category="CVE-2020-14343", target="requirements.txt:2")
    res = ThreatIntelAgent().enrich_run([f], ScanTarget())
    assert res.status == "ok"
    ti = f.enrichment["threat_intel"]["CVE-2020-14343"]
    assert ti["affected"] == "yes"
    assert ti["cvss"] == 9.8
    assert ti["fixed_version"] == "5.4"


def test_high_epss_emits_exploitable_finding():
    f = Finding(agent="vuln_scanner", title="pyyaml==5.3.1", category="CVE-2020-14343", target="r.txt")
    res = ThreatIntelAgent().enrich_run([f], ScanTarget())
    extra = [x for x in res.findings if x.agent == "threat_intel"]
    assert any("CVE-2020-14343" in x.category for x in extra)
    assert any(x.correlated_ids == [f.id] for x in extra)


def test_known_malicious_ip_produces_ioc_finding_and_bumps_severity():
    f = Finding(agent="log_monitor", title="probe from 198.51.100.23", category="ATT&CK T1190",
                severity="medium", target="access.log",
                evidence=["198.51.100.23 - - GET /x?id=1 union select"])
    res = ThreatIntelAgent().enrich_run([f], ScanTarget())
    assert f.severity == "high"  # bumped from medium by IOC hit
    ioc = [x for x in res.findings if x.agent == "threat_intel" and "198.51.100.23" in x.title]
    assert ioc


def test_unknown_cve_marked_uncertain():
    f = Finding(agent="vuln_scanner", title="x", category="CVE-1999-0001", target="t")
    ThreatIntelAgent().enrich_run([f], ScanTarget())
    assert f.enrichment["threat_intel"]["CVE-1999-0001"]["affected"] == "uncertain"


def test_bundled_feed_reports_no_timestamp():
    assert BundledFeed().feed_updated() is None
