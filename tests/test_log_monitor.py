from agents.log_monitor import LogMonitorAgent
from agents.log_monitor.detectors import detect_anomalies
from agents.log_monitor.parsers import parse_all
from conftest import FIXTURES


def test_brute_force_detected():
    agent = LogMonitorAgent()
    findings = agent.run([str(FIXTURES / "logs" / "auth_bruteforce.log")])
    brute = [f for f in findings if "brute" in f.title.lower()]
    assert len(brute) == 1
    f = brute[0]
    assert f.category == "ATT&CK:T1110"
    assert len(f.evidence) >= 5
    assert "203.0.113.77" in f.evidence[0]
    assert f.confidence > 0.5


def test_clean_log_yields_no_brute_force():
    agent = LogMonitorAgent()
    findings = agent.run([str(FIXTURES / "logs" / "auth_clean.log")])
    assert all("brute" not in f.title.lower() for f in findings)


def test_missing_log_file_does_not_crash():
    agent = LogMonitorAgent()
    findings = agent.run([str(FIXTURES / "logs" / "does_not_exist.log")])
    assert findings == []


def test_evidence_is_redacted():
    events = parse_all(str(FIXTURES / "logs" / "auth_bruteforce.log"))
    detections = detect_anomalies(events)
    for d in detections:
        for line in d.evidence_lines:
            assert "hunter2" not in line
