"""Run one agent as a standalone worker, or serve the orchestrator over HTTP.

    python -m tools.worker orchestrator --serve 0.0.0.0:8080
    python -m tools.worker vuln_scanner            # filesystem-queue worker

The HTTP server runs the pipeline in-process (it does not fan out to the agent
workers - the single-process orchestrator is the reference implementation). The
agent-worker mode is a minimal filesystem queue included so the docker-compose
topology runs without extra infrastructure. Swap in Redis via CYBERGUARD_QUEUE
for a real deployment.
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from contracts import ScanTarget  # noqa: E402

_AGENTS = {
    "log_monitor": "LogMonitorAgent",
    "threat_intel": "ThreatIntelAgent",
    "vuln_scanner": "VulnerabilityScannerAgent",
    "incident_response": "IncidentResponseAgent",
    "policy_checker": "PolicyCheckerAgent",
}

QUEUE_DIR = os.environ.get("CYBERGUARD_FS_QUEUE", os.path.join(ROOT, ".queue"))


def _make_handler():
    from orchestrator import run_scan

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("", "/health"):
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path.rstrip("/") != "/scan":
                self._send(404, {"error": "POST /scan"})
                return
            length = int(self.headers.get("content-length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
                report = run_scan(ScanTarget.from_dict(data))
                self._send(200, report.to_dict())
            except Exception as exc:  # noqa: BLE001
                self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

        def log_message(self, *_args):  # quieter
            return

    return Handler


def serve(bind: str) -> None:
    host, _, port = bind.partition(":")
    httpd = ThreadingHTTPServer((host or "0.0.0.0", int(port or "8080")), _make_handler())
    print(f"[worker] orchestrator HTTP on {bind} (POST /scan, GET /health)")
    httpd.serve_forever()


def _load_agent(name: str):
    import agents

    return getattr(agents, _AGENTS[name])()


def run_fs_worker(name: str, poll: float = 1.0) -> None:
    inbox = os.path.join(QUEUE_DIR, "in", name)
    outbox = os.path.join(QUEUE_DIR, "out", name)
    os.makedirs(inbox, exist_ok=True)
    os.makedirs(outbox, exist_ok=True)
    agent = _load_agent(name)
    print(f"[worker] {name} watching {inbox}")
    while True:
        tasks = sorted(f for f in os.listdir(inbox) if f.endswith(".json"))
        for task in tasks:
            path = os.path.join(inbox, task)
            try:
                with open(path, encoding="utf-8") as fh:
                    payload = json.load(fh)
                target = ScanTarget.from_dict(payload.get("target", {}))
                result = agent.run(target, payload.get("context", {}))
                out = {
                    "agent": result.agent,
                    "status": result.status,
                    "notes": result.notes,
                    "findings": [f.to_dict() for f in result.findings],
                }
                with open(os.path.join(outbox, task), "w", encoding="utf-8") as fh:
                    json.dump(out, fh, indent=2)
            except Exception as exc:  # noqa: BLE001
                with open(os.path.join(outbox, task), "w", encoding="utf-8") as fh:
                    json.dump({"agent": name, "status": "failed", "error": str(exc)}, fh)
            finally:
                os.remove(path)
        time.sleep(poll)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    role = argv[0]
    if role == "orchestrator":
        bind = "0.0.0.0:8080"
        if "--serve" in argv:
            bind = argv[argv.index("--serve") + 1]
        serve(bind)
        return 0
    if role in _AGENTS:
        run_fs_worker(role)
        return 0
    print(f"unknown role {role!r}; expected 'orchestrator' or one of {sorted(_AGENTS)}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
