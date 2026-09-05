"""FastAPI web UI + REST API.

Endpoints per spec §3 (Interfaces): /scan, /status, /findings, /report
Plus a small server-rendered dashboard at / for the hackathon demo.

Scans run synchronously in a background thread and report progress via an
in-memory status dict — good enough for a single-user demo; a production
deployment would use a real task queue.
"""
from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from contracts import ScanTarget
from orchestrator import Orchestrator
from orchestrator.report_builder import to_markdown
from tools.store import get_store

app = FastAPI(title="Cybersecurity AI Agent System")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
store = get_store()

_jobs: dict[str, dict] = {}  # run_id -> {"status": "...", "error": Optional[str]}
_lock = threading.Lock()


class ScanRequest(BaseModel):
    log_sources: list[str] = []
    repo_path: Optional[str] = None
    image_names: list[str] = []
    openapi_spec: Optional[str] = None
    api_base_url: Optional[str] = None
    allow_active: bool = False
    target_allowlist: list[str] = []
    compliance_framework: str = "NIST CSF 2.0"


def _run_scan_background(job_id: str, target: ScanTarget) -> None:
    with _lock:
        _jobs[job_id] = {"status": "running", "error": None, "run_id": None}
    try:
        orch = Orchestrator()
        report = orch.run_scan(target)
        with _lock:
            _jobs[job_id] = {"status": "complete", "error": None, "run_id": report.run_id}
    except Exception as exc:  # fail safe — never leave a job hanging silently
        with _lock:
            _jobs[job_id] = {"status": "failed", "error": str(exc), "run_id": None}


@app.post("/scan")
def start_scan(req: ScanRequest):
    target = ScanTarget(**req.model_dump())
    job_id = uuid.uuid4().hex[:12]
    thread = threading.Thread(target=_run_scan_background, args=(job_id, target), daemon=True)
    thread.start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/status")
def status(job_id: Optional[str] = None):
    if job_id:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job_id")
        return {"job_id": job_id, **job}
    return {"jobs": _jobs}


@app.get("/findings")
def findings(run_id: str):
    report = store.get_report(run_id)
    if not report:
        raise HTTPException(404, "unknown run_id")
    return [f.model_dump() for f in report.findings]


@app.get("/report")
def report(run_id: str, format: str = "json"):
    r = store.get_report(run_id)
    if not r:
        raise HTTPException(404, "unknown run_id")
    if format == "markdown":
        return HTMLResponse(content=to_markdown(r), media_type="text/markdown")
    return r.model_dump()


@app.get("/runs")
def list_runs():
    return store.list_runs()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    runs = store.list_runs()
    return templates.TemplateResponse("dashboard.html", {"request": request, "runs": runs})


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str):
    r = store.get_report(run_id)
    if not r:
        raise HTTPException(404, "unknown run_id")
    return templates.TemplateResponse("run_detail.html", {"request": request, "report": r})
