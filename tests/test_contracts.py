from contracts import Finding, stable_finding_id


def test_finding_id_is_deterministic():
    id1 = stable_finding_id("log_monitor", "auth.log", "brute_force:1.2.3.4")
    id2 = stable_finding_id("log_monitor", "auth.log", "brute_force:1.2.3.4")
    assert id1 == id2


def test_finding_id_differs_by_signature():
    id1 = stable_finding_id("log_monitor", "auth.log", "brute_force:1.2.3.4")
    id2 = stable_finding_id("log_monitor", "auth.log", "brute_force:5.6.7.8")
    assert id1 != id2


def test_finding_new_sets_defaults():
    f = Finding.new(
        agent="log_monitor", title="t", description="d", severity="high",
        confidence=0.8, category="ATT&CK:T1110", target="auth.log",
        signature="sig1",
    )
    assert f.requires_human_approval is True
    assert f.evidence == []
    assert f.correlated_ids == []
