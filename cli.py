#!/usr/bin/env python3
"""CLI entrypoint.

Usage:
  python cli.py scan --repo demo/sample_repo --logs demo/logs/auth.log,demo/logs/access.log
  python cli.py list-runs
  python cli.py show-report <run_id>
"""
from __future__ import annotations

import argparse
import sys

from contracts import ScanTarget
from orchestrator import Orchestrator
from orchestrator.report_builder import to_console_summary, to_markdown
from tools.store import get_store


def cmd_scan(args: argparse.Namespace) -> int:
    target = ScanTarget(
        log_sources=args.logs.split(",") if args.logs else [],
        repo_path=args.repo,
        image_names=args.images.split(",") if args.images else [],
        openapi_spec=args.openapi,
        api_base_url=args.api_base_url,
        allow_active=args.allow_active,
        target_allowlist=args.allowlist.split(",") if args.allowlist else [],
        compliance_framework=args.framework,
    )
    orch = Orchestrator()
    report = orch.run_scan(target)
    print(to_console_summary(report))
    if args.markdown_out:
        with open(args.markdown_out, "w") as f:
            f.write(to_markdown(report))
        print(f"Markdown report written to {args.markdown_out}")
    return 0


def cmd_list_runs(args: argparse.Namespace) -> int:
    store = get_store()
    for run in store.list_runs():
        print(f"{run['run_id']}  {run['started_at']}  {run['target_summary']}")
    return 0


def cmd_show_report(args: argparse.Namespace) -> int:
    store = get_store()
    report = store.get_report(args.run_id)
    if not report:
        print(f"No such run: {args.run_id}", file=sys.stderr)
        return 1
    print(to_markdown(report))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-agent cybersecurity scan CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run a scan")
    p_scan.add_argument("--repo", default=None, help="Path to a repo to scan")
    p_scan.add_argument("--logs", default=None, help="Comma-separated log file paths")
    p_scan.add_argument("--images", default=None, help="Comma-separated container image names")
    p_scan.add_argument("--openapi", default=None, help="Path to an OpenAPI spec")
    p_scan.add_argument("--api-base-url", default=None, dest="api_base_url")
    p_scan.add_argument("--allow-active", action="store_true", dest="allow_active",
                         help="Allow active scanning against the allowlist")
    p_scan.add_argument("--allowlist", default=None, help="Comma-separated allowed hosts")
    p_scan.add_argument("--framework", default="NIST CSF 2.0")
    p_scan.add_argument("--markdown-out", default=None, dest="markdown_out")
    p_scan.set_defaults(func=cmd_scan)

    p_list = sub.add_parser("list-runs", help="List past scan runs")
    p_list.set_defaults(func=cmd_list_runs)

    p_show = sub.add_parser("show-report", help="Show a past run's report as markdown")
    p_show.add_argument("run_id")
    p_show.set_defaults(func=cmd_show_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
