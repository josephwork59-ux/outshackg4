"""Generates the seeded demo log fixtures deterministically. Run once (already
checked in under demo/logs/) — kept here so the scenario is reproducible /
inspectable rather than a checked-in mystery blob.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

OUT = Path(__file__).parent / "logs"
OUT.mkdir(exist_ok=True)

BASE_TS = "Jan 15 03:1{0}:00"


def gen_auth_log() -> str:
    lines = []
    users = ["root", "admin", "postgres", "ubuntu", "test"]
    # Brute force cluster from a single attacker IP — should trip
    # detect_brute_force with attack technique T1110.
    for i in range(12):
        u = users[i % len(users)]
        lines.append(f"Jan 15 03:{10+i:02d}:00 web01 sshd[10{i}]: Failed password for {u} from 203.0.113.77 port 4210{i} ssh2")
    # A second, smaller cluster — below threshold, should NOT trigger alone.
    for i in range(3):
        lines.append(f"Jan 15 04:0{i}:00 web01 sshd[20{i}]: Failed password for deploy from 198.51.100.23 port 5000{i} ssh2")
    # A legitimate successful login from a known IP.
    lines.append("Jan 15 08:00:00 web01 sshd[300]: Accepted password for deploy from 10.0.0.5 port 55000 ssh2")
    # A successful login from an unrecognized IP (new-geo heuristic).
    lines.append("Jan 15 02:00:00 web01 sshd[301]: Accepted password for admin from 45.33.22.11 port 55010 ssh2")
    # Privilege escalation indicator.
    lines.append("Jan 15 03:25:00 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/usermod -aG root deploy")
    # Log tampering indicator.
    lines.append("Jan 15 03:26:00 web01 auditd[500]: auditd stopped, keeping current audit configuration")
    return "\n".join(lines) + "\n"


def gen_access_log() -> str:
    lines = []
    ts = "15/Jan/2026:03:30:00 +0000"
    # Port/path scan from one IP across many distinct paths.
    scan_paths = ["/admin", "/wp-login.php", "/.env", "/config.php", "/phpmyadmin",
                  "/.git/config", "/api/v1/debug", "/server-status", "/actuator/health", "/xmlrpc.php"]
    for i, p in enumerate(scan_paths):
        lines.append(f'198.51.100.23 - - [{ts}] "GET {p} HTTP/1.1" 404 153')
    # SQLi injection probes.
    for i in range(3):
        lines.append(
            f'203.0.113.77 - - [{ts}] "GET /products?id=1%20OR%201=1--%20 HTTP/1.1" 200 512'
        )
    # XSS probe.
    lines.append(f'203.0.113.77 - - [{ts}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 480')
    # Normal traffic.
    for i in range(5):
        lines.append(f'10.0.0.9 - - [{ts}] "GET /index.html HTTP/1.1" 200 1024')
    return "\n".join(lines) + "\n"


def gen_app_json_log() -> str:
    lines = []
    base_t = 1768450000.0
    # Baseline small transfers.
    for i in range(6):
        lines.append(json.dumps({
            "ts": base_t + i * 60, "source_ip": "10.0.0.9", "user": "svc-app",
            "action": "export_report", "status": "200", "bytes_out": 4200 + i * 100,
        }))
    # Exfil anomaly — far above baseline.
    lines.append(json.dumps({
        "ts": base_t + 500, "source_ip": "203.0.113.77", "user": "svc-app",
        "action": "export_report", "status": "200", "bytes_out": 512_000_000,
    }))
    # C2 beacon — periodic connections to the same dest_ip every 30s.
    for i in range(6):
        lines.append(json.dumps({
            "ts": base_t + 1000 + i * 30, "dest_ip": "91.203.5.10",
            "action": "outbound_connect", "status": "established",
        }))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    (OUT / "auth.log").write_text(gen_auth_log())
    (OUT / "access.log").write_text(gen_access_log())
    (OUT / "app.json.log").write_text(gen_app_json_log())
    print("wrote", list(OUT.iterdir()))
