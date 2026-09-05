from agents.incident_response import IncidentResponseAgent
from contracts import Finding, IncidentPhase


def _finding(severity="critical", confidence=0.9):
    return Finding.new(
        agent="log_monitor", title="SSH brute-force from 1.2.3.4",
        description="d", severity=severity, confidence=confidence,
        category="ATT&CK:T1110", target="auth.log", signature="brute_force:1.2.3.4",
        evidence=["Failed password for root from 1.2.3.4"],
        recommended_fix="Enforce lockout.",
    )


def test_plan_has_all_four_phases():
    agent = IncidentResponseAgent()
    plan = agent.build_plan(_finding())
    phases = {s.phase for s in plan.steps}
    assert phases == {IncidentPhase.CONTAIN, IncidentPhase.ERADICATE,
                       IncidentPhase.RECOVER, IncidentPhase.POST_INCIDENT}


def test_all_steps_require_human_approval():
    agent = IncidentResponseAgent()
    plan = agent.build_plan(_finding())
    assert all(s.requires_human_approval for s in plan.steps)


def test_critical_finding_gets_p1():
    agent = IncidentResponseAgent()
    plan = agent.build_plan(_finding(severity="critical"))
    assert plan.priority == "P1"
    assert plan.sla_target == "1 hour"


def test_run_only_plans_high_severity_or_high_confidence():
    agent = IncidentResponseAgent()
    low = _finding(severity="low", confidence=0.2)
    high = _finding(severity="high", confidence=0.9)
    plans = agent.run([low, high], min_severity="high", min_confidence=0.7)
    assert len(plans) == 1
    assert plans[0].finding_id == high.id
