"""Vulnerability Scanner Agent - scan code, dependencies, Dockerfiles, and images.

Wraps real scanners (semgrep, bandit, pip-audit, trivy, hadolint) when they are
installed; otherwise falls back to built-in checks and reports status "partial".
All code scanning is read-only. Active API testing is gated behind
`target.allow_active` AND an explicit host allowlist - by default it is skipped
and only an informational finding is recorded.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Iterable

from contracts import AgentResult, Finding, ScanTarget
from tools import external
from tools.redaction import looks_like_secret, redact
from tools.versioning import satisfies

from .base import DATA_DIR, Agent

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}
_TEXT_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".go", ".java", ".php", ".sh",
    ".env", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".txt", ".tf", ".conf",
}
_SEVERITY_BY_CVSS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def _sev_from_cvss(cvss: float | None) -> str:
    if not cvss:
        return "medium"
    for threshold, label in _SEVERITY_BY_CVSS:
        if cvss >= threshold:
            return label
    return "info"


class VulnerabilityScannerAgent(Agent):
    name = "vuln_scanner"
    role = "Scan code, APIs, and Docker images to find security weaknesses."
    system_prompt = (
        "You are the Vulnerability Scanner Agent. Wrap real scanners; do not reinvent "
        "them. Report one finding per weakness with file:line or image layer, a CWE / "
        "OWASP category, severity, the fixed version or concrete patch, a short proof "
        "snippet (redacted), and a false-positive likelihood. Do not run active network "
        "tests unless explicitly allowed and the target is on the allowlist. Never edit "
        "the code you scan."
    )

    def __init__(self, data_dir: str = DATA_DIR) -> None:
        with open(os.path.join(data_dir, "cve_db.json"), encoding="utf-8") as fh:
            self._cve = json.load(fh).get("packages", {})

    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:
        findings: list[Finding] = []
        notes: list[str] = []
        degraded = False

        if target.repo_path and os.path.isdir(target.repo_path):
            dep_f, dep_notes, dep_degraded = self._scan_dependencies(target.repo_path)
            sec_f, sec_notes = self._scan_secrets(target.repo_path)
            code_f, code_notes, code_degraded = self._scan_code(target.repo_path)
            findings += dep_f + sec_f + code_f
            notes += dep_notes + sec_notes + code_notes
            degraded = degraded or dep_degraded or code_degraded
        else:
            notes.append("no repo_path or path not a directory; skipped code/dependency scan")

        for df in target.dockerfiles:
            df_f, df_notes, df_degraded = self._scan_dockerfile(df)
            findings += df_f
            notes += df_notes
            degraded = degraded or df_degraded

        for image in target.images:
            img_f, img_notes, img_degraded = self._scan_image(image)
            findings += img_f
            notes += img_notes
            degraded = degraded or img_degraded

        if target.api_endpoints:
            findings += self._api_note(target)

        status = "partial" if degraded else ("ok" if findings or notes else "partial")
        return AgentResult(self.name, findings, status, notes)

    # --- dependencies ---------------------------------------------------

    def _iter_requirements(self, repo: str) -> Iterable[str]:
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                if name == "requirements.txt" or re.match(r"requirements.*\.txt$", name):
                    yield os.path.join(root, name)

    def _scan_dependencies(self, repo: str) -> tuple[list[Finding], list[str], bool]:
        findings: list[Finding] = []
        notes: list[str] = []
        degraded = False

        req_files = list(self._iter_requirements(repo))
        for req in req_files:
            # Prefer the real tool when present.
            tr = external.run_pip_audit(req)
            if tr.available and tr.data is not None:
                notes.append(f"pip-audit scanned {os.path.relpath(req, repo)}")
                findings += self._from_pip_audit(tr.data, req, repo)
                continue
            if tr.available:
                notes.append(f"pip-audit ran on {os.path.relpath(req, repo)} but output was unusable; used built-in matcher")
            else:
                notes.append("pip-audit not installed; used built-in advisory matcher for requirements")
                degraded = True
            findings += self._builtin_dep_match(req, repo)

        if not req_files:
            notes.append("no requirements*.txt found")
        return findings, notes, degraded

    def _builtin_dep_match(self, req_path: str, repo: str) -> list[Finding]:
        findings: list[Finding] = []
        rel = os.path.relpath(req_path, repo)
        try:
            lines = open(req_path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            return findings
        for lineno, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+-]+)", line)
            if not m:
                continue
            pkg, ver = m.group(1).lower(), m.group(2)
            for rec in self._cve.get(pkg, []):
                if not satisfies(ver, rec["affected"]):
                    continue
                sev = _sev_from_cvss(rec.get("cvss"))
                findings.append(
                    Finding(
                        agent=self.name,
                        title=f"Vulnerable dependency: {pkg}=={ver} ({rec['cve']})",
                        description=rec.get("summary", ""),
                        severity=sev,
                        confidence=0.8,
                        category=rec["cve"],
                        target=f"{rel}:{lineno}",
                        signature=f"dep:{pkg}:{rec['cve']}",
                        evidence=[f"{rel}:{lineno}: {raw.strip()}"],
                        references=rec.get("references", []),
                        recommended_fix=f"Upgrade {pkg} to >= {rec['fixed']} (fixes {rec['cve']}).",
                        enrichment={
                            "package": pkg,
                            "installed_version": ver,
                            "fixed_version": rec["fixed"],
                            "cvss": rec.get("cvss"),
                            "cwe": rec.get("cwe"),
                        },
                    )
                )
        return findings

    def _from_pip_audit(self, data: Any, req_path: str, repo: str) -> list[Finding]:
        rel = os.path.relpath(req_path, repo)
        out: list[Finding] = []
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        for dep in deps or []:
            name = dep.get("name", "?")
            version = dep.get("version", "?")
            for vuln in dep.get("vulns", []) or []:
                vid = vuln.get("id", "UNKNOWN")
                fix_versions = ", ".join(vuln.get("fix_versions", []) or []) or "a patched release"
                out.append(
                    Finding(
                        agent=self.name,
                        title=f"Vulnerable dependency: {name}=={version} ({vid})",
                        description=vuln.get("description", "")[:500],
                        severity="high",
                        confidence=0.85,
                        category=vid if vid.upper().startswith("CVE") else f"OSV:{vid}",
                        target=rel,
                        signature=f"dep:{name}:{vid}",
                        evidence=[f"{rel}: {name}=={version}"],
                        references=vuln.get("aliases", []),
                        recommended_fix=f"Upgrade {name} to {fix_versions}.",
                        enrichment={"package": name, "installed_version": version},
                    )
                )
        return out

    # --- secrets ------------------------------------------------------

    def _scan_secrets(self, repo: str) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        scanned = 0
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext and ext not in _TEXT_EXT and name != "Dockerfile":
                    continue
                path = os.path.join(root, name)
                if os.path.getsize(path) > 512_000:
                    continue
                scanned += 1
                try:
                    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
                except OSError:
                    continue
                for lineno, line in enumerate(lines, 1):
                    rule = looks_like_secret(line)
                    if rule:
                        rel = os.path.relpath(path, repo)
                        findings.append(
                            Finding(
                                agent=self.name,
                                title=f"Hardcoded secret ({rule}) in {rel}:{lineno}",
                                description="A credential-like string is committed to the repository.",
                                severity="high",
                                confidence=0.6,
                                category="CWE-798",
                                target=f"{rel}:{lineno}",
                                signature=f"secret:{rel}:{lineno}:{rule}",
                                evidence=[f"{rel}:{lineno}: {redact(line.strip())}"],
                                references=["https://cwe.mitre.org/data/definitions/798.html"],
                                recommended_fix=(
                                    "Revoke/rotate the credential now, remove it from git history, "
                                    "and load it from a secrets manager or environment variable."
                                ),
                                enrichment={"rule": rule, "false_positive_likelihood": "medium"},
                            )
                        )
        return findings, [f"secret scan checked {scanned} text file(s)"]

    # --- code (semgrep/bandit) -------------------------------------

    def _scan_code(self, repo: str) -> tuple[list[Finding], list[str], bool]:
        notes: list[str] = []
        findings: list[Finding] = []
        ran_any = False

        sg = external.run_semgrep(repo)
        if sg.available and sg.data is not None:
            ran_any = True
            for res in sg.data.get("results", []):
                extra = res.get("extra", {})
                sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
                    str(extra.get("severity", "")).upper(), "medium"
                )
                rel = os.path.relpath(res.get("path", "?"), repo)
                line = res.get("start", {}).get("line", 0)
                findings.append(
                    Finding(
                        agent=self.name,
                        title=f"semgrep: {res.get('check_id', 'rule')}",
                        description=extra.get("message", "")[:500],
                        severity=sev,
                        confidence=0.7,
                        category=str((extra.get("metadata", {}) or {}).get("cwe", "code-scan")),
                        target=f"{rel}:{line}",
                        signature=f"semgrep:{res.get('check_id')}:{rel}:{line}",
                        evidence=[redact(str(extra.get("lines", "")))[:300]],
                        references=list((extra.get("metadata", {}) or {}).get("references", []) or []),
                        recommended_fix=extra.get("fix", "") or "Review and remediate per the rule guidance.",
                    )
                )
            notes.append(f"semgrep produced {len(sg.data.get('results', []))} result(s)")
        else:
            notes.append(sg.note or "semgrep not available")

        bd = external.run_bandit(repo)
        if bd.available and bd.data is not None:
            ran_any = True
            for res in bd.data.get("results", []):
                sev = str(res.get("issue_severity", "MEDIUM")).lower()
                rel = os.path.relpath(res.get("filename", "?"), repo)
                findings.append(
                    Finding(
                        agent=self.name,
                        title=f"bandit: {res.get('test_id')} {res.get('test_name')}",
                        description=res.get("issue_text", "")[:500],
                        severity=sev if sev in ("high", "medium", "low") else "medium",
                        confidence=0.65,
                        category=f"CWE-{(res.get('issue_cwe') or {}).get('id', '')}".rstrip("-"),
                        target=f"{rel}:{res.get('line_number', 0)}",
                        signature=f"bandit:{res.get('test_id')}:{rel}:{res.get('line_number')}",
                        evidence=[redact(str(res.get("code", "")))[:300]],
                        references=[(res.get("issue_cwe") or {}).get("link", "")],
                        recommended_fix="Apply the secure pattern recommended by bandit for this test.",
                    )
                )
            notes.append(f"bandit produced {len(bd.data.get('results', []))} result(s)")
        else:
            notes.append(bd.note or "bandit not available")

        return findings, notes, not ran_any

    # --- dockerfile ----------------------------------------------------

    def _scan_dockerfile(self, path: str) -> tuple[list[Finding], list[str], bool]:
        try:
            content = open(path, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            return [], [f"could not read Dockerfile {path}: {exc}"], False

        lines = content.splitlines()
        findings: list[Finding] = []
        has_user_nonroot = False
        notes: list[str] = []

        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            low = line.lower()
            if low.startswith("user ") and "root" not in low and low.split()[1] not in ("0", "root"):
                has_user_nonroot = True

            if low.startswith("from ") and (":" not in line.split()[1] or line.split()[1].endswith(":latest")):
                findings.append(self._df_finding(
                    path, lineno, raw, "Unpinned base image (`:latest` or no tag)",
                    "medium", "CWE-1188",
                    "Pin the base image to an immutable digest (FROM image@sha256:...).",
                ))
            if low.startswith("add ") and re.search(r"https?://", line):
                findings.append(self._df_finding(
                    path, lineno, raw, "ADD used to fetch a remote URL",
                    "medium", "CWE-494",
                    "Use COPY for local files; download with verified checksums in a RUN step.",
                ))
            if re.search(r"(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash)\b", low):
                findings.append(self._df_finding(
                    path, lineno, raw, "Piping a downloaded script straight into a shell",
                    "high", "CWE-494",
                    "Download, verify a checksum/signature, then execute.",
                ))
            if re.search(r"--no-check-certificate|--insecure\b|verify\s*=\s*false", low):
                findings.append(self._df_finding(
                    path, lineno, raw, "TLS verification disabled during build",
                    "high", "CWE-295",
                    "Remove the insecure flag and trust the correct CA.",
                ))
            if (low.startswith("env ") or low.startswith("arg ")) and looks_like_secret(line):
                findings.append(self._df_finding(
                    path, lineno, raw, "Secret-like value in ENV/ARG",
                    "high", "CWE-798",
                    "Use build secrets / runtime secrets, never bake credentials into layers.",
                ))
            if re.search(r"apt-get\s+install", low) and "rm -rf /var/lib/apt/lists" not in content:
                findings.append(self._df_finding(
                    path, lineno, raw, "apt-get install without cleaning apt lists",
                    "low", "CWE-1188",
                    "Append `&& rm -rf /var/lib/apt/lists/*` to shrink layers and attack surface.",
                ))

        if not has_user_nonroot:
            findings.append(self._df_finding(
                path, len(lines) or 1, "(no USER instruction)",
                "Container runs as root (no non-root USER instruction)",
                "high", "CWE-250",
                "Add a non-root `USER` instruction and make required paths writable by that UID.",
            ))

        notes.append(f"parsed Dockerfile {os.path.basename(path)} ({len(findings)} issue(s))")
        return findings, notes, False

    def _df_finding(self, path, lineno, raw, title, severity, cwe, fix) -> Finding:
        base = os.path.basename(path)
        return Finding(
            agent=self.name,
            title=f"{title} in {base}:{lineno}",
            description=title,
            severity=severity,
            confidence=0.75,
            category=cwe,
            target=f"{path}:{lineno}",
            signature=f"dockerfile:{path}:{lineno}:{title[:24]}",
            evidence=[f"{base}:{lineno}: {redact(str(raw).strip())}"],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"],
            recommended_fix=fix,
            enrichment={"artifact": "dockerfile"},
        )

    # --- image (trivy) ----------------------------------------------

    def _scan_image(self, image: str) -> tuple[list[Finding], list[str], bool]:
        tr = external.run_trivy_image(image)
        if not tr.available:
            return (
                [Finding(
                    agent=self.name,
                    title=f"Image not scanned: {image} (trivy not installed)",
                    description="Install trivy to scan container images for OS/library CVEs, misconfig, and secrets.",
                    severity="info",
                    confidence=0.9,
                    category="coverage-gap",
                    target=image,
                    signature=f"image-skip:{image}",
                    recommended_fix="Install aquasecurity/trivy and re-run the scan.",
                )],
                [f"trivy not installed; image {image} not scanned"],
                True,
            )
        if tr.data is None:
            return [], [f"trivy ran on {image} but output was unusable"], True

        findings: list[Finding] = []
        for res in tr.data.get("Results", []) or []:
            tgt = res.get("Target", image)
            for v in res.get("Vulnerabilities", []) or []:
                sev = str(v.get("Severity", "MEDIUM")).lower()
                findings.append(
                    Finding(
                        agent=self.name,
                        title=f"{image}: {v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('VulnerabilityID')}",
                        description=(v.get("Title") or v.get("Description") or "")[:500],
                        severity=sev if sev in ("critical", "high", "medium", "low") else "medium",
                        confidence=0.85,
                        category=v.get("VulnerabilityID", "CVE"),
                        target=f"{image}::{tgt}",
                        signature=f"trivy:{image}:{v.get('PkgName')}:{v.get('VulnerabilityID')}",
                        evidence=[f"{v.get('PkgName')} {v.get('InstalledVersion')} in {tgt}"],
                        references=v.get("References", [])[:5],
                        recommended_fix=f"Update {v.get('PkgName')} to {v.get('FixedVersion') or 'a fixed release'}.",
                        enrichment={"package": v.get("PkgName"), "fixed_version": v.get("FixedVersion")},
                    )
                )
        return findings, [f"trivy found {len(findings)} vulnerability finding(s) in {image}"], False

    # --- api (passive only) --------------------------------------

    def _api_note(self, target: ScanTarget) -> list[Finding]:
        allowed = [e for e in target.api_endpoints if any(a in e for a in target.allowlist)]
        if target.allow_active and allowed:
            # Active probing intentionally not implemented in this build. It must be
            # added deliberately, and only against `allowed`.
            return [Finding(
                agent=self.name,
                title="Active API testing requested but not implemented in this build",
                description=(
                    f"{len(allowed)} endpoint(s) are on the allowlist and --allow-active is set, "
                    "but this build ships no active HTTP prober. Add one deliberately."
                ),
                severity="info",
                confidence=0.9,
                category="coverage-gap",
                target=",".join(allowed),
                signature="api-active-not-implemented",
                recommended_fix="Implement a bounded, allowlisted API prober (authz, rate-limit, headers, error verbosity).",
            )]
        return [Finding(
            agent=self.name,
            title="API active testing skipped (no --allow-active / not on allowlist)",
            description=(
                f"{len(target.api_endpoints)} endpoint(s) provided. Active testing requires "
                "target.allow_active=true and each host present in target.allowlist."
            ),
            severity="info",
            confidence=0.95,
            category="coverage-gap",
            target=",".join(target.api_endpoints),
            signature="api-skipped",
            recommended_fix="Re-run with allow_active and an explicit allowlist to enable API checks.",
        )]
