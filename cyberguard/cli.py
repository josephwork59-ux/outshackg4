"""CyberGuard CLI.

    python -m cli scan     --config demo/scenario.json [--out reports/] [--json]
    python -m cli report   --report reports/<run>.json
    python -m cli findings  --report reports/<run>.json [--min-severity high]
    python -m cli status   --report reports/<run>.json

`scan` is the entry point; the others re-render a saved report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contracts import ScanTarget, SEVERITY_RANK  # noqa: E402
from orchestrator import build_report_files, render_console, run_scan  # noqa: E402


def _cmd_scan(args) -> int:
    target = ScanTarget.from_json(args.config)
    report = run_scan(target)
    json_path, md_path = build_report_files(report, args.out)
    print(render_console(report))
    print(f"\nwrote {json_path}\nwrote {md_path}")
    if args.json:
        print(report.to_json())
    # exit non-zero if any critical/high finding exists (useful in CI gates)
    worst = max((SEVERITY_RANK[f.severity] for f in report.findings), default=0)
    return 2 if worst >= SEVERITY_RANK["high"] else 0


def _load_report_dict(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _cmd_report(args) -> int:
    data = _load_report_dict(args.report)
    # re-render markdown straight from the stored dict
    print(_markdown_from_dict(data))
    return 0


def _cmd_findings(args) -> int:
    data = _load_report_dict(args.report)
    floor = SEVERITY_RANK.get(args.min_severity, 0)
    rows = [f for f in data["findings"] if SEVERITY_RANK.get(f["severity"], 0) >= floor]
    rows.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)
    for f in rows:
        print(f"[{f['severity']:>8}] {f['id']}  {f['agent']:<16} {f['title']}")
    print(f"\n{len(rows)} finding(s) at or above '{args.min_severity}'")
    return 0


def _cmd_status(args) -> int:
    data = _load_report_dict(args.report)
    for agent, st in data["agent_status"].items():
        print(f"{agent:<20} {st}")
    return 0


def _markdown_from_dict(data: dict) -> str:
    # Minimal reconstruction so `report` works without re-running the scan.
    lines = [f"# CyberGuard Scan Report - {data['run_id']}", ""]
    lines.append(data.get("executive_summary", ""))
    lines.append("")
    lines.append("## Findings")
    for f in sorted(data["findings"], key=lambda x: SEVERITY_RANK.get(x["severity"], 0), reverse=True):
        lines.append(f"- [{f['severity']}] {f['title']}  (`{f['id']}`, {f['agent']})")
    if data.get("compliance"):
        c = data["compliance"]
        lines.append("")
        lines.append(f"## Compliance - {c['framework']} {c['framework_version']} "
                     f"(coverage {c['coverage_pct']}%)")
        for a in c["assessments"]:
            lines.append(f"- {a['control_id']} {a['title']}: **{a['status']}**")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cyberguard", description="Multi-agent security scanner (proposal-only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a full multi-agent scan")
    s.add_argument("--config", required=True, help="path to a ScanTarget JSON file")
    s.add_argument("--out", default="reports", help="output directory for the report files")
    s.add_argument("--json", action="store_true", help="also print the full JSON report")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("report", help="render a saved report as markdown")
    r.add_argument("--report", required=True)
    r.set_defaults(func=_cmd_report)

    f = sub.add_parser("findings", help="list findings from a saved report")
    f.add_argument("--report", required=True)
    f.add_argument("--min-severity", default="info", choices=list(SEVERITY_RANK))
    f.set_defaults(func=_cmd_findings)

    st = sub.add_parser("status", help="show agent status from a saved report")
    st.add_argument("--report", required=True)
    st.set_defaults(func=_cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
