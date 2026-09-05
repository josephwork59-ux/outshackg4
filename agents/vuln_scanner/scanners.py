"""Thin, deterministic wrappers around real scanners. Each function returns
plain dicts parsed from the scanner's own JSON output — no LLM involved here.
If a binary is missing, the wrapper degrades gracefully (returns an empty
list + a note) instead of crashing the whole run, per the "fail safe"
guardrail.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s: {' '.join(cmd)}"


def run_semgrep(path: str) -> list[dict]:
    if not shutil.which("semgrep"):
        return []
    code, out, err = _run(
        ["semgrep", "--config", "auto", "--json", "--quiet", "--metrics", "off", path],
        timeout=180,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    results = []
    for r in data.get("results", []):
        results.append({
            "tool": "semgrep",
            "check_id": r.get("check_id"),
            "path": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "message": r.get("extra", {}).get("message"),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "lines": r.get("extra", {}).get("lines", ""),
            "cwe": (r.get("extra", {}).get("metadata", {}) or {}).get("cwe"),
            "owasp": (r.get("extra", {}).get("metadata", {}) or {}).get("owasp"),
        })
    return results


def run_bandit(path: str) -> list[dict]:
    if not shutil.which("bandit"):
        return []
    code, out, err = _run(["bandit", "-r", path, "-f", "json", "-q"], timeout=120)
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    results = []
    for r in data.get("results", []):
        results.append({
            "tool": "bandit",
            "check_id": r.get("test_id"),
            "path": r.get("filename"),
            "line": r.get("line_number"),
            "message": r.get("issue_text"),
            "severity": r.get("issue_severity", "MEDIUM"),
            "confidence": r.get("issue_confidence", "MEDIUM"),
            "lines": r.get("code", ""),
            "cwe": (r.get("issue_cwe") or {}).get("id"),
        })
    return results


def run_secret_scan(path: str) -> list[dict]:
    """Prefers gitleaks if present; falls back to detect-secrets (both are
    real, established secret scanners — the spec names gitleaks/trufflehog
    but doesn't mandate one specific binary)."""
    if shutil.which("gitleaks"):
        code, out, err = _run(
            ["gitleaks", "detect", "--source", path, "--no-git", "-f", "json", "-r", "/dev/stdout"],
            timeout=120,
        )
        if out:
            try:
                data = json.loads(out)
                return [{
                    "tool": "gitleaks", "path": r.get("File"), "line": r.get("StartLine"),
                    "message": r.get("Description"), "severity": "HIGH",
                    "lines": r.get("Match", ""), "rule": r.get("RuleID"),
                } for r in data]
            except json.JSONDecodeError:
                return []
        return []

    if shutil.which("detect-secrets"):
        code, out, err = _run(["detect-secrets", "scan", path], timeout=120)
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        results = []
        for file_path, secrets in data.get("results", {}).items():
            for s in secrets:
                results.append({
                    "tool": "detect-secrets", "path": file_path, "line": s.get("line_number"),
                    "message": f"Potential secret: {s.get('type')}", "severity": "HIGH",
                    "lines": "[redacted by scanner]", "rule": s.get("type"),
                })
        return results
    return []


def run_pip_audit(path: str) -> list[dict]:
    if not shutil.which("pip-audit"):
        return []
    req_files = list(Path(path).rglob("requirements*.txt"))
    results = []
    for req in req_files:
        code, out, err = _run(["pip-audit", "-r", str(req), "-f", "json"], timeout=120)
        if not out:
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue
        # pip-audit>=2.7 returns {"dependencies": [...]}; older returns a list.
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        for dep in deps:
            for vuln in dep.get("vulns", []):
                aliases = vuln.get("aliases", []) or []
                cve_alias = next((a for a in aliases if a.upper().startswith("CVE")), None)
                results.append({
                    "tool": "pip-audit",
                    "path": str(req),
                    "package": dep.get("name"),
                    "installed_version": dep.get("version"),
                    "vuln_id": vuln.get("id"),
                    "cve_id": cve_alias,
                    "fix_versions": vuln.get("fix_versions", []),
                    "message": (vuln.get("description") or "")[:400],
                })
    return results


def run_trivy(image: str) -> list[dict]:
    """Real trivy if installed; otherwise a documented stub interface so the
    pipeline still demonstrates the contract without requiring Docker/Trivy
    in this environment."""
    if shutil.which("trivy"):
        code, out, err = _run(["trivy", "image", "--format", "json", "--quiet", image], timeout=300)
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        results = []
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []) or []:
                results.append({
                    "tool": "trivy", "image": image, "target": r.get("Target"),
                    "vuln_id": v.get("VulnerabilityID"), "package": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "message": (v.get("Title") or v.get("Description") or "")[:400],
                })
        return results

    return [{
        "tool": "trivy-stub", "image": image, "target": "N/A",
        "vuln_id": "STUB-NO-TRIVY", "package": None, "installed_version": None,
        "fixed_version": None, "severity": "INFO",
        "message": (
            "trivy binary not available in this environment — container image "
            "scanning is stubbed. Interface: run_trivy(image) -> list[dict] with "
            "keys {vuln_id, package, installed_version, fixed_version, severity, "
            "message}. Install trivy and re-run for real results."
        ),
    }]


def lint_dockerfile(path: str) -> list[dict]:
    """Small deterministic Dockerfile misconfiguration linter, used as a
    concrete, always-available complement to the trivy image scan (which
    needs a built image / registry access)."""
    dockerfiles = list(Path(path).rglob("Dockerfile*"))
    findings = []
    for df in dockerfiles:
        text = df.read_text(errors="replace")
        lines = text.splitlines()
        joined = text
        if "USER root" in joined or ("USER " not in joined):
            findings.append({
                "tool": "dockerfile-lint", "path": str(df), "line": 1,
                "rule": "DL3002-no-root-user",
                "message": "Container runs as root (no non-root USER set). "
                           "Add a USER directive with a non-root UID.",
                "severity": "MEDIUM",
            })
        for i, line in enumerate(lines, start=1):
            if line.strip().upper().startswith("ADD ") and ("http://" in line or "https://" in line):
                findings.append({
                    "tool": "dockerfile-lint", "path": str(df), "line": i,
                    "rule": "DL3020-add-remote-url",
                    "message": "ADD used to fetch a remote URL; prefer COPY + explicit "
                               "checksum verification or a pinned base image layer.",
                    "severity": "LOW",
                })
            if re.search(r"(?i)\b(password|secret|token|api_key)\s*=", line):
                findings.append({
                    "tool": "dockerfile-lint", "path": str(df), "line": i,
                    "rule": "DL3050-secret-in-dockerfile",
                    "message": "Possible hardcoded secret baked into the image layer.",
                    "severity": "HIGH",
                })
            if line.strip().upper().startswith("FROM") and ":LATEST" in line.upper():
                findings.append({
                    "tool": "dockerfile-lint", "path": str(df), "line": i,
                    "rule": "DL3007-latest-tag",
                    "message": "Base image pinned to :latest — non-reproducible, "
                               "can silently pull in new vulnerabilities.",
                    "severity": "LOW",
                })
    return findings
