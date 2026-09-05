from agents.policy_checker import PolicyCheckerAgent
from contracts import Finding


def _dep_finding(severity="high"):
    return Finding.new(
        agent="vuln_scanner", title="vulnerable dependency: flask (CVE-2019-1010083)",
        description="d", severity=severity, confidence=0.9, category="dependency-vuln",
        target="requirements.txt :: flask==0.12", signature="pip-audit:CVE-2019-1010083:flask",
        recommended_fix="Upgrade to 1.0",
    )


def test_no_findings_gives_met_for_pass_on_no_findings_controls():
    agent = PolicyCheckerAgent()
    report = agent.run([], [])
    ra01 = next(a for a in report.assessments if a.control_id == "ID.RA-01")
    assert ra01.status == "Met"


def test_high_severity_finding_marks_control_not_met():
    agent = PolicyCheckerAgent()
    report = agent.run([_dep_finding("high")], [])
    ps02 = next(a for a in report.assessments if a.control_id == "PR.PS-02")
    assert ps02.status == "Not Met"
    assert ps02.evidence_finding_ids


def test_framework_label_is_explicit():
    agent = PolicyCheckerAgent()
    report = agent.run([], [])
    assert report.framework == "NIST CSF"
    assert report.framework_version == "2.0"
    assert "subset" in report.control_subset_note.lower()


def test_coverage_percent_bounds():
    agent = PolicyCheckerAgent()
    report = agent.run([_dep_finding("high")], [])
    assert 0.0 <= report.coverage_percent <= 100.0
