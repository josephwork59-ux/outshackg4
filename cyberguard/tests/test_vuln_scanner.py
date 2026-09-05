import os
import textwrap

from agents import VulnerabilityScannerAgent
from contracts import ScanTarget


def test_builtin_dependency_matcher_flags_known_cve(tmp_path):
    (tmp_path / "requirements.txt").write_text("PyYAML==5.3.1\nrequests==2.31.0\n")
    res = VulnerabilityScannerAgent().run(ScanTarget(repo_path=str(tmp_path)))
    cves = [f for f in res.findings if f.category == "CVE-2020-14343"]
    assert cves, "PyYAML 5.3.1 should match CVE-2020-14343"
    f = cves[0]
    assert f.enrichment["fixed_version"] == "5.4"
    assert "5.4" in f.recommended_fix
    assert f.evidence and "requirements.txt" in f.evidence[0]
    # a patched package must NOT be flagged
    assert not [f for f in res.findings if "requests" in f.title.lower()]


def test_secret_scan_flags_hardcoded_key(tmp_path):
    (tmp_path / "settings.py").write_text('AWS_ACCESS_KEY_ID = "AKIAJ7EXAMPLE9DEMO42"\n')
    res = VulnerabilityScannerAgent().run(ScanTarget(repo_path=str(tmp_path)))
    secrets = [f for f in res.findings if f.category == "CWE-798"]
    assert secrets
    # evidence is redacted
    assert "AKIAJ7EXAMPLE9DEMO42" not in " ".join(secrets[0].evidence)


def test_dockerfile_checks(fixtures_dir):
    res = VulnerabilityScannerAgent().run(
        ScanTarget(dockerfiles=[os.path.join(fixtures_dir, "Dockerfile.bad")])
    )
    titles = " ".join(f.title for f in res.findings)
    assert "Unpinned base image" in titles
    assert "runs as root" in titles
    assert "ADD used to fetch a remote URL" in titles
    assert "Piping a downloaded script" in titles


def test_api_endpoints_without_allow_active_are_skipped_safely():
    res = VulnerabilityScannerAgent().run(
        ScanTarget(api_endpoints=["https://x.example/v1"], allow_active=False)
    )
    skipped = [f for f in res.findings if f.signature == "api-skipped"]
    assert skipped and skipped[0].severity == "info"


def test_no_repo_is_not_a_crash():
    res = VulnerabilityScannerAgent().run(ScanTarget())
    assert res.status in ("ok", "partial")
