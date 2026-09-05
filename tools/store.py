"""Findings Store: the shared state layer between agents and the orchestrator.

Per the hackathon-scoped decision: no external message bus. Handoff between
agents within one run is plain in-process asyncio (see orchestrator/graph.py);
this module is the *persistence* layer — every run, finding, incident plan
and compliance report is written to a local SQLite file so runs are durable,
inspectable with any SQLite tool, and the web UI / REST API can read them
without holding process state in memory.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from contracts import ComplianceReport, Finding, IncidentPlan, ScanReport

DB_PATH = Path(__file__).resolve().parent.parent / "reports" / "findings.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT,
    finished_at TEXT,
    target_summary TEXT,
    agent_status TEXT,
    executive_summary TEXT,
    compliance_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    agent TEXT,
    severity TEXT,
    confidence REAL,
    category TEXT,
    target TEXT,
    json TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS incident_plans (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    finding_id TEXT,
    priority TEXT,
    json TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
"""


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


class FindingsStore:
    """Thin persistence wrapper. Deliberately synchronous + simple — this is
    a decision-support demo, not a high-throughput event system."""

    def init(self) -> None:
        with _conn():
            pass

    def save_report(self, report: ScanReport) -> None:
        with _conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO runs
                   (run_id, started_at, finished_at, target_summary, agent_status,
                    executive_summary, compliance_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.run_id,
                    report.started_at.isoformat(),
                    report.finished_at.isoformat() if report.finished_at else None,
                    report.target_summary,
                    json.dumps(report.agent_status),
                    report.executive_summary,
                    report.compliance.model_dump_json() if report.compliance else None,
                ),
            )
            for f in report.findings:
                self._save_finding(conn, report.run_id, f)
            for p in report.incident_plans:
                self._save_plan(conn, report.run_id, p)

    def _save_finding(self, conn: sqlite3.Connection, run_id: str, f: Finding) -> None:
        conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, run_id, agent, severity, confidence, category, target, json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (f.id, run_id, f.agent, f.severity, f.confidence, f.category, f.target,
             f.model_dump_json()),
        )

    def _save_plan(self, conn: sqlite3.Connection, run_id: str, p: IncidentPlan) -> None:
        conn.execute(
            """INSERT OR REPLACE INTO incident_plans
               (id, run_id, finding_id, priority, json)
               VALUES (?, ?, ?, ?, ?)""",
            (p.id, run_id, p.finding_id, p.priority, p.model_dump_json()),
        )

    def list_runs(self) -> list[dict]:
        with _conn() as conn:
            rows = conn.execute(
                "SELECT run_id, started_at, finished_at, target_summary FROM runs "
                "ORDER BY started_at DESC"
            ).fetchall()
            return [
                {"run_id": r[0], "started_at": r[1], "finished_at": r[2], "target_summary": r[3]}
                for r in rows
            ]

    def get_report(self, run_id: str) -> ScanReport | None:
        with _conn() as conn:
            row = conn.execute(
                "SELECT run_id, started_at, finished_at, target_summary, agent_status, "
                "executive_summary, compliance_json FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if not row:
                return None
            findings = [
                Finding.model_validate_json(r[0])
                for r in conn.execute("SELECT json FROM findings WHERE run_id=?", (run_id,))
            ]
            plans = [
                IncidentPlan.model_validate_json(r[0])
                for r in conn.execute(
                    "SELECT json FROM incident_plans WHERE run_id=?", (run_id,)
                )
            ]
            compliance = ComplianceReport.model_validate_json(row[6]) if row[6] else None
            return ScanReport(
                run_id=row[0],
                started_at=row[1],
                finished_at=row[2],
                target_summary=row[3],
                findings=findings,
                incident_plans=plans,
                compliance=compliance,
                agent_status=json.loads(row[4]) if row[4] else {},
                executive_summary=row[5] or "",
            )


_default_store: FindingsStore | None = None


def get_store() -> FindingsStore:
    global _default_store
    if _default_store is None:
        _default_store = FindingsStore()
        _default_store.init()
    return _default_store
