"""End-to-end pipeline test against the demo fixtures — mirrors the
acceptance criteria in the project spec."""
from conftest import ROOT
from contracts import ScanTarget
from orchestrator import Orchestrator


def test_full_pipeline_against_demo_fixtures():
    demo_dir = ROOT / "demo"
    target = ScanTarget(
        log_sources=[str(demo_dir / "logs" / "auth.log"), str(demo_dir / "logs" / "access.log")],
        repo_path=str(demo_dir / "sample_repo"),
        compliance_framework="NIST CSF 2.0",
    )
    orch = Orchestrator()
    report = orch.run_scan(target)

    assert len(report.findings) >= 1
    assert any(f.agent == "log_monitor" for f in report.findings)
    assert any(f.agent == "vuln_scanner" for f in report.findings)
    assert report.compliance is not None
    assert all(status != "" for status in report.agent_status.values())
    # No agent performed a mutating action: every finding that could change
    # state is flagged for human approval.
    assert all(f.requires_human_approval for f in report.findings)


def test_partial_report_on_empty_target():
    target = ScanTarget()  # no logs, no repo, no images
    orch = Orchestrator()
    report = orch.run_scan(target)
    assert report.findings == []
    assert report.agent_status["log_monitor"] == "skipped"


def test_out_of_scope_active_scan_is_refused():
    target = ScanTarget(
        allow_active=True, api_base_url="http://example.com",
        target_allowlist=["other-host.example.com"],
    )
    orch = Orchestrator()
    report = orch.run_scan(target)
    assert report.agent_status.get("orchestrator") == "partial"
