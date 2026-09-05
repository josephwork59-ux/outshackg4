#!/usr/bin/env python3
"""End-to-end demo: runs the full multi-agent pipeline against the seeded
fixtures in demo/logs and demo/sample_repo, and prints + saves the report.

This is what `make demo` calls (see acceptance criteria in the project spec).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import ScanTarget  # noqa: E402
from orchestrator import Orchestrator  # noqa: E402
from orchestrator.report_builder import to_console_summary, to_markdown  # noqa: E402

DEMO_DIR = Path(__file__).parent
REPORTS_DIR = ROOT / "reports"


def main() -> int:
    target = ScanTarget(
        log_sources=[
            str(DEMO_DIR / "logs" / "auth.log"),
            str(DEMO_DIR / "logs" / "access.log"),
            str(DEMO_DIR / "logs" / "app.json.log"),
        ],
        repo_path=str(DEMO_DIR / "sample_repo"),
        image_names=[],  # no real image built for the demo; trivy wrapper stubs gracefully
        openapi_spec=str(DEMO_DIR / "sample_repo" / "openapi.json"),
        allow_active=False,
        target_allowlist=[],
        compliance_framework="NIST CSF 2.0",
    )

    orch = Orchestrator()
    report = orch.run_scan(target)

    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "sample_scan_report.json").write_text(report.model_dump_json(indent=2))
    (REPORTS_DIR / "sample_scan_report.md").write_text(to_markdown(report))

    print(to_console_summary(report))
    print(f"\nFull report written to:\n  {REPORTS_DIR / 'sample_scan_report.json'}\n  {REPORTS_DIR / 'sample_scan_report.md'}")

    if report.agent_status.get("orchestrator") == "partial" and not report.findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
