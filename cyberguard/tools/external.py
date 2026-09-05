"""Thin, best-effort wrappers around real security scanners.

Design rules:
  * Never reinvent a scanner - shell out to the real one when it is installed.
  * If the binary is missing, return `available=False`; the caller degrades to
    built-in checks and marks its agent status "partial". A missing tool is
    never a run failure.
  * Read-only invocations only. Nothing here changes state or scans the network.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_TIMEOUT = 120


@dataclass
class ToolRun:
    tool: str
    available: bool
    ok: bool = False
    data: Any = None
    stdout: str = ""
    stderr: str = ""
    note: str = ""
    findings_raw: list[dict] = field(default_factory=list)


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_json_tool(tool: str, cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> ToolRun:
    if not _which(tool):
        return ToolRun(tool=tool, available=False, note=f"{tool} not installed; skipped")
    try:
        proc = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ToolRun(tool=tool, available=True, ok=False, note=f"{tool} timed out")
    except OSError as exc:  # pragma: no cover - environment dependent
        return ToolRun(tool=tool, available=True, ok=False, note=f"{tool} failed to launch: {exc}")

    data: Any = None
    if proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            data = None
    return ToolRun(
        tool=tool,
        available=True,
        ok=proc.returncode in (0, 1),  # many scanners exit 1 when findings exist
        data=data,
        stdout=proc.stdout[:20000],
        stderr=proc.stderr[:4000],
        note="" if data is not None else f"{tool} produced no parseable JSON",
    )


def run_semgrep(path: str) -> ToolRun:
    return run_json_tool("semgrep", ["semgrep", "--quiet", "--json", "--config", "auto", path])


def run_bandit(path: str) -> ToolRun:
    return run_json_tool("bandit", ["bandit", "-r", "-q", "-f", "json", path])


def run_pip_audit(path: str) -> ToolRun:
    return run_json_tool("pip-audit", ["pip-audit", "-f", "json", "-r", path])


def run_trivy_image(image: str) -> ToolRun:
    return run_json_tool(
        "trivy",
        ["trivy", "image", "--quiet", "--scanners", "vuln,misconfig,secret", "-f", "json", image],
        timeout=300,
    )


def run_hadolint(dockerfile: str) -> ToolRun:
    return run_json_tool("hadolint", ["hadolint", "-f", "json", dockerfile])
