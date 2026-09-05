from agents.vuln_scanner import VulnScannerAgent
from agents.vuln_scanner import scanners
from contracts import ScanTarget
from conftest import FIXTURES


def test_pip_audit_finds_known_vulnerable_flask():
    results = scanners.run_pip_audit(str(FIXTURES / "repo"))
    packages = {r["package"] for r in results}
    assert "flask" in packages
    cve_ids = {r.get("cve_id") for r in results}
    assert "CVE-2019-1010083" in cve_ids


def test_agent_produces_dependency_findings():
    agent = VulnScannerAgent()
    target = ScanTarget(repo_path=str(FIXTURES / "repo"))
    findings = agent.run(target)
    dep_findings = [f for f in findings if f.category == "dependency-vuln"]
    assert len(dep_findings) > 0
    assert any(f.cve_ids for f in dep_findings)


def test_dockerfile_lint_flags_root_user(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nCOPY . .\nCMD [\"python\", \"app.py\"]\n")
    results = scanners.lint_dockerfile(str(tmp_path))
    rules = {r["rule"] for r in results}
    assert "DL3002-no-root-user" in rules
    assert "DL3007-latest-tag" in rules


def test_no_repo_path_returns_no_findings():
    agent = VulnScannerAgent()
    target = ScanTarget()
    findings = agent.run(target)
    assert findings == []
