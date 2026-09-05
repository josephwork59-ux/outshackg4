import os

from agents import LogMonitorAgent
from contracts import ScanTarget


def _run(fixtures_dir, *names_formats):
    sources = [{"path": os.path.join(fixtures_dir, n), "format": f} for n, f in names_formats]
    return LogMonitorAgent().run(ScanTarget(log_sources=sources))


def test_detects_brute_force_with_attack_id_and_evidence(fixtures_dir):
    res = _run(fixtures_dir, ("auth_bruteforce.log", "syslog"))
    bf = [f for f in res.findings if "T1110" in f.category]
    assert bf, "expected a brute-force finding"
    f = bf[0]
    assert f.evidence, "brute-force finding must cite log lines"
    assert "192.0.2.50" in f.title
    # success from the same IP after failures -> escalated to critical
    assert f.severity == "critical"
    assert f.enrichment["breached"] is True


def test_detects_web_probes(fixtures_dir):
    res = _run(fixtures_dir, ("access_probes.log", "nginx"))
    cats = " ".join(f.category for f in res.findings)
    titles = " ".join(f.title for f in res.findings)
    assert "T1190" in cats
    assert "SQL injection probe" in titles
    assert "Path traversal" in titles or "LFI" in titles


def test_missing_source_degrades_to_partial(fixtures_dir):
    res = LogMonitorAgent().run(ScanTarget(log_sources=[
        {"path": os.path.join(fixtures_dir, "auth_bruteforce.log"), "format": "syslog"},
        {"path": os.path.join(fixtures_dir, "nope.log"), "format": "syslog"},
    ]))
    assert res.status == "partial"
    assert res.findings  # still produced results from the readable source


def test_no_sources_is_partial():
    res = LogMonitorAgent().run(ScanTarget(log_sources=[]))
    assert res.status == "partial"
    assert res.findings == []
