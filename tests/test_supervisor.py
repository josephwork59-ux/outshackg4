from contracts import Finding
from orchestrator import supervisor


def _f(target, sig, severity="medium", **kw):
    return Finding.new(
        agent="vuln_scanner", title=sig, description="d", severity=severity,
        confidence=0.6, category="dependency-vuln", target=target, signature=sig, **kw
    )


def test_dedupe_removes_exact_duplicates():
    f1 = _f("repo/app.py:10", "sig1")
    f2 = _f("repo/app.py:10", "sig1")  # identical -> same id
    merged = supervisor.dedupe([f1, f2])
    assert len(merged) == 1


def test_correlate_links_shared_target():
    f1 = _f("repo/app.py:10", "sig1")
    f2 = _f("repo/app.py:10", "sig2")
    supervisor.correlate([f1, f2])
    assert f2.id in f1.correlated_ids
    assert f1.id in f2.correlated_ids


def test_kev_upgrades_severity():
    f = _f("x", "sig1", severity="medium", kev=True)
    supervisor.finalize_severity([f])
    assert f.severity in ("high", "critical")


def test_merge_and_prioritize_sorts_by_severity():
    low = _f("a", "s1", severity="low")
    crit = _f("b", "s2", severity="critical")
    merged = supervisor.merge_and_prioritize([low, crit])
    assert merged[0].id == crit.id
