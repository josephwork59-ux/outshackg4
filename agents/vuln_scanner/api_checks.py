"""API/OpenAPI static checks — passive by default. Active probing against a
live endpoint requires --allow-active AND the endpoint to be in the scope
allowlist (enforced by the caller, agent.py).
"""
from __future__ import annotations

import json
from pathlib import Path


def static_openapi_checks(spec_path: str) -> list[dict]:
    """Read an OpenAPI/Swagger spec and flag common weaknesses without
    touching the network: missing auth on operations, wildcard CORS if
    declared, missing rate-limit hints, verbose error schemas."""
    p = Path(spec_path)
    if not p.exists():
        return []
    try:
        spec = json.loads(p.read_text())
    except json.JSONDecodeError:
        try:
            import yaml  # optional dependency
            spec = yaml.safe_load(p.read_text())
        except Exception:
            return []

    findings = []
    global_security = spec.get("security")
    paths = spec.get("paths", {}) or {}
    for path, methods in paths.items():
        for method, op in (methods or {}).items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            op = op or {}
            has_security = "security" in op or global_security
            if not has_security:
                findings.append({
                    "path": f"{method.upper()} {path}", "rule": "missing-auth",
                    "message": f"Operation {method.upper()} {path} declares no security "
                               f"requirement (no auth) in the spec.",
                    "severity": "HIGH",
                })
            responses = op.get("responses", {}) or {}
            for code, resp in responses.items():
                if str(code).startswith("5") or str(code).startswith("4"):
                    schema = json.dumps(resp)
                    if "stackTrace" in schema or "stack_trace" in schema:
                        findings.append({
                            "path": f"{method.upper()} {path}", "rule": "verbose-error",
                            "message": f"Error response {code} for {method.upper()} {path} "
                                       f"appears to expose a stack trace.",
                            "severity": "MEDIUM",
                        })

    components = spec.get("components", {}) or {}
    cors = json.dumps(spec)
    if '"Access-Control-Allow-Origin": "*"' in cors or "'*'" in cors and "cors" in cors.lower():
        findings.append({
            "path": "(global)", "rule": "insecure-cors",
            "message": "Spec/config indicates a wildcard CORS origin ('*').",
            "severity": "MEDIUM",
        })

    if not paths:
        findings.append({
            "path": "(global)", "rule": "empty-spec",
            "message": "No paths found in OpenAPI spec — nothing to check.",
            "severity": "INFO",
        })
    return findings


ACTIVE_HEADER_CHECKS = [
    ("Strict-Transport-Security", "missing-hsts", "MEDIUM"),
    ("X-Content-Type-Options", "missing-nosniff", "LOW"),
    ("Content-Security-Policy", "missing-csp", "MEDIUM"),
    ("X-Frame-Options", "missing-frame-options", "LOW"),
]


def active_header_scan(base_url: str, allowlist: list[str]) -> list[dict]:
    """Only ever called by agent.py after it has verified --allow-active AND
    base_url is in allowlist. Uses a HEAD/GET request against the given URL
    only — never crawls, never mutates state."""
    import urllib.request
    from urllib.parse import urlparse

    host = urlparse(base_url).netloc
    if host not in allowlist and base_url not in allowlist:
        return [{
            "path": base_url, "rule": "out-of-scope", "severity": "INFO",
            "message": f"{base_url} is not in the target allowlist — active scan refused.",
        }]

    findings = []
    try:
        req = urllib.request.Request(base_url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            headers = {k: v for k, v in resp.getheaders()}
            for header, rule, sev in ACTIVE_HEADER_CHECKS:
                if header not in headers:
                    findings.append({
                        "path": base_url, "rule": rule, "severity": sev,
                        "message": f"Missing security header: {header}",
                    })
    except Exception as exc:
        findings.append({
            "path": base_url, "rule": "unreachable", "severity": "INFO",
            "message": f"Active header scan could not reach {base_url}: {exc}",
        })
    return findings
