from agents import IncidentResponseAgent
from contracts import Finding, ScanTarget


def _plan(**kw):
    f = Finding(agent="x", title=kw.get("title", "t"), category=kw.get("category", ""),
               severity=kw.get("severity", "high"), target="svc",
               enrichment=kw.get("enrichment", {}))
    return IncidentResponseAgent().plan_for([f], ScanTarget(**kw.get("target", {}))), f


def test_plan_has_all_four_phases_and_approval_gates():
    plan, _ = _plan(category="ATT&CK T1110", title="Brute-force from 203.0.113.66")
    phases = [s.phase for s in plan.steps]
    for phase in ("contain", "eradicate", "recover", "post-incident"):
        assert phase in phases
    assert any(s.requires_human_approval for s in plan.steps)
    assert plan.required_approvals
    assert plan.evidence_preservation


def test_state_changing_steps_are_gated():
    plan, _ = _plan(category="CVE-2020-14343", title="Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343)")
    for s in plan.steps:
        if s.command_or_change:
            assert s.requires_human_approval, f"{s.action} changes state but is not gated"


def test_priority_escalates_when_actively_exploited():
    plan_hi, _ = _plan(category="CVE-2020-14343", title="dep", severity="high",
                       enrichment={"exploited_in_wild": True})
    plan_lo, _ = _plan(category="CVE-2020-14343", title="dep", severity="high")
    assert plan_hi.priority == "P1"
    assert plan_lo.priority == "P2"


def test_comms_draft_is_marked_draft():
    plan, _ = _plan(category="CWE-798", title="Hardcoded secret in settings.py")
    assert "DRAFT" in plan.comms_draft.upper()
