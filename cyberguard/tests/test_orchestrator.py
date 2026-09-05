import json

from orchestrator import render_console, render_markdown, run_scan


def test_full_scan_over_demo_scenario(demo_target):
    report = run_scan(demo_target)

    agents_with_findings = {f.agent for f in report.findings}
    assert {"log_monitor", "vuln_scanner", "threat_intel"}.issubset(agents_with_findings)

    # brute force with ATT&CK id + evidence
    bf = [f for f in report.findings if f.agent == "log_monitor" and "T1110" in f.category]
    assert bf and bf[0].evidence

    # vulnerable dependency -> CVE with fixed version, enriched by threat intel
    dep = [f for f in report.findings
           if f.agent == "vuln_scanner" and f.category.upper().startswith("CVE-")]
    assert dep
    assert any(f.enrichment.get("threat_intel") for f in report.findings)

    # at least one incident plan, fully phased, with an approval gate
    assert report.incident_plans
    p = report.incident_plans[0]
    assert {"contain", "eradicate", "recover", "post-incident"} <= {s.phase for s in p.steps}
    assert any(s.requires_human_approval for s in p.steps)

    # compliance mapped with gaps
    assert report.compliance and report.compliance.failing_controls
    assert report.compliance.finding_control_matrix

    # nothing executed: no state-changing step is left ungated
    ungated = [s for pl in report.incident_plans for s in pl.steps
               if s.command_or_change and not s.requires_human_approval]
    assert not ungated

    # serializable
    round_trip = json.loads(report.to_json())
    assert round_trip["run_id"] == report.run_id


def test_cross_agent_correlation_links_shared_ip(demo_target):
    report = run_scan(demo_target)
    # 203.0.113.66 appears in the brute-force finding, a traversal probe, and the IOC finding
    linked = [f for f in report.findings if f.correlated_ids]
    assert linked, "expected at least one correlated finding"
    corr = report.target_summary.get("correlations", [])
    assert any(c["type"] == "shared-ip" and "203.0.113.66" == c["key"] for c in corr)


def test_severity_escalation_recorded(demo_target):
    report = run_scan(demo_target)
    adjusted = [f for f in report.findings if f.enrichment.get("severity_adjustment")]
    # external exposure + high asset criticality should push at least one finding up
    assert adjusted


def test_agent_status_present_for_all(demo_target):
    report = run_scan(demo_target)
    for agent in ("log_monitor", "vuln_scanner", "threat_intel",
                  "incident_response", "policy_checker"):
        assert agent in report.agent_status


def test_render_helpers_run(demo_target):
    report = run_scan(demo_target)
    assert report.run_id in render_markdown(report)
    assert "proposed only" in render_console(report)
