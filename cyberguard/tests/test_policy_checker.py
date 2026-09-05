import pytest

from agents import PolicyCheckerAgent
from contracts import Finding, ScanTarget


def _findings():
    return [
        Finding(agent="vuln_scanner", title="Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343)",
                category="CVE-2020-14343", severity="critical", target="requirements.txt:2"),
        Finding(agent="log_monitor", title="Brute-force / credential-stuffing from 203.0.113.66",
                category="ATT&CK T1110", severity="high", target="auth.log"),
        Finding(agent="vuln_scanner", title="Hardcoded secret (aws) in settings.py",
                category="CWE-798", severity="high", target="settings.py:4"),
    ]


@pytest.mark.parametrize("framework", ["NIST_CSF", "SOC2", "ISO27001"])
def test_each_framework_produces_failing_controls_and_matrix(framework):
    report = PolicyCheckerAgent().assess(_findings(), framework)
    assert report.framework_version
    assert report.subset_note
    assert report.failing_controls, "expected some Not Met / Partial controls"
    assert report.finding_control_matrix, "expected finding -> control mapping"
    # every mapped control id is real
    ids = {a.control_id for a in report.assessments}
    for ctrls in report.finding_control_matrix.values():
        assert set(ctrls).issubset(ids)


def test_cve_finding_maps_to_vuln_mgmt_control():
    report = PolicyCheckerAgent().assess(_findings(), "ISO27001")
    matrix_vals = {c for v in report.finding_control_matrix.values() for c in v}
    assert "A.8.8" in matrix_vals  # management of technical vulnerabilities


def test_no_pass_without_evidence():
    report = PolicyCheckerAgent().assess(_findings(), "NIST_CSF")
    for a in report.assessments:
        if a.status == "Met":
            assert a.evidence_finding_ids, "a Met control must cite evidence"
    # controls with no related finding are 'Not Assessed', never 'Met'
    assert any(a.status == "Not Assessed" for a in report.assessments)


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        PolicyCheckerAgent().assess(_findings(), "PCI")


def test_run_over_never_raises_and_sets_status():
    report, status, notes = PolicyCheckerAgent().run_over(_findings(), ScanTarget(framework="SOC2"))
    assert status == "ok"
    assert report is not None
    assert notes
