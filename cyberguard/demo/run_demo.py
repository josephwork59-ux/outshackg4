"""Run the full pipeline against the seeded demo environment and check the
acceptance criteria from the build prompt.

    python -m demo.run_demo         (from the cyberguard/ directory)
    make demo

Exits 0 only if every acceptance check passes.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)  # so the relative paths in scenario.json resolve

from agents import LogMonitorAgent  # noqa: E402
from contracts import ScanTarget  # noqa: E402
from orchestrator import build_report_files, render_console, run_scan  # noqa: E402

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))


def main() -> int:
    target = ScanTarget.from_json("demo/scenario.json")
    report = run_scan(target)
    json_path, md_path = build_report_files(report, "reports")

    print(render_console(report))
    print(f"\nwrote {json_path}\nwrote {md_path}\n")

    by_agent: dict[str, list] = {}
    for f in report.findings:
        by_agent.setdefault(f.agent, []).append(f)

    # 1. at least one finding from each of the three scanning agents
    for a in ("log_monitor", "vuln_scanner", "threat_intel"):
        check(f"{a} produced >=1 finding", len(by_agent.get(a, [])) >= 1,
              f"{len(by_agent.get(a, []))} findings")

    # 2. brute force detected with cited log lines + ATT&CK id
    bf = [f for f in by_agent.get("log_monitor", [])
          if "T1110" in f.category and f.evidence]
    check("brute-force detected with ATT&CK id + evidence", bool(bf),
          bf[0].title if bf else "none")

    # 3. vulnerable dependency matched to a CVE with fixed version + KEV/EPSS note
    dep = [f for f in by_agent.get("vuln_scanner", [])
           if f.category.upper().startswith("CVE-") and f.enrichment.get("fixed_version")]
    ti_note = False
    for f in report.findings:
        for ti in (f.enrichment.get("threat_intel") or {}).values():
            if ti.get("epss") is not None or ti.get("kev") is not None:
                ti_note = True
    check("vulnerable dependency matched to CVE with fixed version", bool(dep),
          dep[0].title if dep else "none")
    check("threat intel attached a KEV/EPSS note", ti_note)

    # 4. at least one incident plan with all four phases + a human-approval step
    good_plan = None
    for p in report.incident_plans:
        phases = {s.phase for s in p.steps}
        if {"contain", "eradicate", "recover", "post-incident"}.issubset(phases) and any(
            s.requires_human_approval for s in p.steps
        ):
            good_plan = p
            break
    check("incident plan has all 4 phases + human-approval gate", good_plan is not None,
          good_plan.title if good_plan else "none")

    # 5. compliance report lists failing controls + finding->control mapping
    c = report.compliance
    check("compliance report present", c is not None)
    check("compliance lists failing/partial controls",
          bool(c and c.failing_controls), str(c.failing_controls) if c else "none")
    check("finding -> control matrix populated",
          bool(c and c.finding_control_matrix),
          f"{len(c.finding_control_matrix)} mapped findings" if c else "none")

    # 6. nothing was executed: every state-changing step is gated for human approval
    ungated = [
        (p.title, s.action)
        for p in report.incident_plans
        for s in p.steps
        if s.command_or_change and not s.requires_human_approval
    ]
    check("all state-changing steps require human approval", not ungated, str(ungated[:2]))

    # 8. a partially-unreadable log source degrades to 'partial', not a crash
    mixed = ScanTarget(log_sources=[
        {"path": "demo/env/var/log/auth.log", "format": "syslog"},
        {"path": "demo/env/var/log/does-not-exist.log", "format": "syslog"},
    ])
    res = LogMonitorAgent().run(mixed)
    check("missing log source -> partial (no crash)", res.status == "partial", res.status)

    print("Acceptance checks")
    print("-" * 68)
    failed = 0
    for name, ok, detail in CHECKS:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        extra = f"  ({detail})" if detail else ""
        print(f"  [{mark}] {name}{extra}")
    print("-" * 68)
    print(f"{len(CHECKS) - failed}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
