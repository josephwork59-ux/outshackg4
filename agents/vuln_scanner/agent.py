from __future__ import annotations

import time

from contracts import Finding, ScanTarget
from tools.audit import RunAuditLog
from tools.llm_client import LLMClient, get_llm_client
from tools.redact import redact

from . import api_checks, scanners

_SEV_MAP_UPPER = {"CRITICAL": "critical", "ERROR": "high", "HIGH": "high",
                   "WARNING": "medium", "MEDIUM": "medium", "LOW": "low",
                   "INFO": "info", "UNKNOWN": "medium"}


def _norm_sev(raw: str | None) -> str:
    return _SEV_MAP_UPPER.get((raw or "MEDIUM").upper(), "medium")


class VulnScannerAgent:
    name = "vuln_scanner"

    def __init__(self, llm: LLMClient | None = None, audit: RunAuditLog | None = None):
        self.llm = llm or get_llm_client()
        self.audit = audit

    def run(self, target: ScanTarget) -> list[Finding]:
        t0 = time.time()
        findings: list[Finding] = []

        if target.repo_path:
            findings += self._scan_repo(target.repo_path)

        if target.image_names:
            for image in target.image_names:
                findings += self._scan_image(image)

        if target.openapi_spec:
            findings += self._scan_openapi(target.openapi_spec)

        if target.allow_active and target.api_base_url:
            findings += self._scan_api_active(target.api_base_url, target.target_allowlist)

        if self.audit:
            self.audit.log_agent_output(self.name, "ok", len(findings), time.time() - t0)
        return findings

    def _tool(self, tool: str, args: dict, fn, *fargs):
        t0 = time.time()
        result = fn(*fargs)
        if self.audit:
            self.audit.log_tool_call(self.name, tool, args, time.time() - t0,
                                      f"{len(result)} raw results")
        return result

    def _scan_repo(self, path: str) -> list[Finding]:
        out: list[Finding] = []

        for r in self._tool("run_semgrep", {"path": path}, scanners.run_semgrep, path):
            out.append(Finding.new(
                agent=self.name, title=f"semgrep: {r.get('check_id')}",
                description=redact(r.get("message") or ""),
                severity=_norm_sev(r.get("severity")), confidence=0.75,
                category=f"CWE-{r.get('cwe')}" if r.get("cwe") else "OWASP-A03",
                target=f"{r.get('path')}:{r.get('line')}",
                signature=f"semgrep:{r.get('check_id')}:{r.get('path')}:{r.get('line')}",
                evidence=[redact(r.get("lines") or "")],
                recommended_fix="See semgrep rule guidance for this check_id; apply the suggested fix pattern.",
            ))

        for r in self._tool("run_bandit", {"path": path}, scanners.run_bandit, path):
            out.append(Finding.new(
                agent=self.name, title=f"bandit: {r.get('check_id')} — {r.get('message', '')[:60]}",
                description=redact(r.get("message") or ""),
                severity=_norm_sev(r.get("severity")), confidence=0.7,
                category=f"CWE-{r.get('cwe')}" if r.get("cwe") else "CWE-unknown",
                target=f"{r.get('path')}:{r.get('line')}",
                signature=f"bandit:{r.get('check_id')}:{r.get('path')}:{r.get('line')}",
                evidence=[redact(r.get("lines") or "")],
                recommended_fix="Review bandit documentation for this test id and apply the secure pattern.",
                references=[f"https://bandit.readthedocs.io/en/latest/plugins/index.html#{(r.get('check_id') or '').lower()}"],
            ))

        for r in self._tool("run_secret_scan", {"path": path}, scanners.run_secret_scan, path):
            out.append(Finding.new(
                agent=self.name, title=f"secret detected: {r.get('rule', 'unknown')}",
                description=redact(r.get("message") or ""),
                severity="critical", confidence=0.8,
                category="CWE-798",
                target=f"{r.get('path')}:{r.get('line')}",
                signature=f"secret:{r.get('rule')}:{r.get('path')}:{r.get('line')}",
                evidence=[redact(str(r.get("lines") or ""))],
                recommended_fix="Revoke and rotate the exposed credential immediately; remove from history; use a secrets manager.",
            ))

        for r in self._tool("run_pip_audit", {"path": path}, scanners.run_pip_audit, path):
            fix_versions = r.get("fix_versions") or []
            cve_id = r.get("cve_id")
            out.append(Finding.new(
                agent=self.name,
                title=f"vulnerable dependency: {r.get('package')} ({cve_id or r.get('vuln_id')})",
                description=redact(r.get("message") or ""),
                severity="high", confidence=0.9,
                category="dependency-vuln",
                target=f"{r.get('path')} :: {r.get('package')}=={r.get('installed_version')}",
                signature=f"pip-audit:{r.get('vuln_id')}:{r.get('package')}",
                evidence=[f"{r.get('package')}=={r.get('installed_version')} matches {r.get('vuln_id')}"],
                references=[f"https://osv.dev/vulnerability/{r.get('vuln_id')}"],
                recommended_fix=(
                    f"Upgrade {r.get('package')} to {fix_versions[0]}" if fix_versions
                    else f"No fixed version published yet for {r.get('vuln_id')}; monitor advisory."
                ),
                cve_ids=[cve_id] if cve_id else [],
            ))

        for r in self._tool("lint_dockerfile", {"path": path}, scanners.lint_dockerfile, path):
            out.append(Finding.new(
                agent=self.name, title=f"Dockerfile misconfig: {r.get('rule')}",
                description=redact(r.get("message") or ""),
                severity=_norm_sev(r.get("severity")), confidence=0.85,
                category="CIS-Docker-Benchmark",
                target=f"{r.get('path')}:{r.get('line')}",
                signature=f"dockerlint:{r.get('rule')}:{r.get('path')}:{r.get('line')}",
                evidence=[r.get("message", "")],
                recommended_fix="Fix per the Dockerfile rule cited (non-root USER, pinned base image, no secrets in layers).",
            ))

        return out

    def _scan_image(self, image: str) -> list[Finding]:
        out = []
        for r in self._tool("run_trivy", {"image": image}, scanners.run_trivy, image):
            out.append(Finding.new(
                agent=self.name,
                title=f"image vuln: {r.get('package') or image} ({r.get('vuln_id')})",
                description=redact(r.get("message") or ""),
                severity=_norm_sev(r.get("severity")), confidence=0.85,
                category="container-image-vuln",
                target=f"{image} :: {r.get('target', '')}",
                signature=f"trivy:{r.get('vuln_id')}:{image}:{r.get('package')}",
                evidence=[f"{r.get('package')}={r.get('installed_version')} in image {image}"],
                recommended_fix=(
                    f"Update {r.get('package')} to {r.get('fixed_version')}"
                    if r.get("fixed_version") else "No fix currently published; track advisory."
                ),
                cve_ids=[r.get("vuln_id")] if (r.get("vuln_id") or "").upper().startswith("CVE") else [],
            ))
        return out

    def _scan_openapi(self, spec_path: str) -> list[Finding]:
        out = []
        for r in self._tool("static_openapi_checks", {"spec": spec_path},
                             api_checks.static_openapi_checks, spec_path):
            out.append(Finding.new(
                agent=self.name, title=f"API spec issue: {r.get('rule')}",
                description=r.get("message", ""),
                severity=_norm_sev(r.get("severity")), confidence=0.6,
                category="OWASP-API-Security-Top-10",
                target=r.get("path", spec_path),
                signature=f"openapi:{r.get('rule')}:{r.get('path')}",
                evidence=[r.get("message", "")],
                recommended_fix="Add explicit auth/security requirements and hardened error handling to the spec.",
            ))
        return out

    def _scan_api_active(self, base_url: str, allowlist: list[str]) -> list[Finding]:
        out = []
        for r in self._tool("active_header_scan", {"url": base_url},
                             api_checks.active_header_scan, base_url, allowlist):
            out.append(Finding.new(
                agent=self.name, title=f"API hardening: {r.get('rule')}",
                description=r.get("message", ""),
                severity=_norm_sev(r.get("severity")), confidence=0.7,
                category="OWASP-API-Security-Top-10",
                target=base_url,
                signature=f"active:{r.get('rule')}:{base_url}",
                evidence=[r.get("message", "")],
                recommended_fix="Add the missing security header at the reverse proxy / app framework level.",
            ))
        return out
