"""Auditability: persist a full run log — inputs, tool calls, agent outputs,
timings, model versions — per guardrail §8. One JSONL file per run under
reports/run_logs/<run_id>.jsonl, append-only.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

LOG_DIR = Path(__file__).resolve().parent.parent / "reports" / "run_logs"


class RunAuditLog:
    def __init__(self, run_id: str):
        self.run_id = run_id
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / f"{run_id}.jsonl"

    def _write(self, event: dict[str, Any]) -> None:
        event["ts"] = time.time()
        event["run_id"] = self.run_id
        with self.path.open("a") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def log_input(self, scan_target: dict) -> None:
        self._write({"type": "input", "scan_target": scan_target})

    def log_tool_call(self, agent: str, tool: str, args: dict, duration_s: float,
                       result_summary: str) -> None:
        self._write({
            "type": "tool_call", "agent": agent, "tool": tool, "args": args,
            "duration_s": duration_s, "result_summary": result_summary,
        })

    def log_agent_output(self, agent: str, status: str, n_findings: int,
                          duration_s: float, model_version: str | None = None) -> None:
        self._write({
            "type": "agent_output", "agent": agent, "status": status,
            "n_findings": n_findings, "duration_s": duration_s,
            "model_version": model_version,
        })

    def log_event(self, message: str, **extra: Any) -> None:
        self._write({"type": "event", "message": message, **extra})

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]
