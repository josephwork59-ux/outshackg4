# Multi-Agent Cybersecurity AI System

A decision-support pipeline of cooperating agents that monitors logs,
scans code/dependencies/containers, enriches findings with threat intel,
checks compliance, and drafts incident-response plans — with a human
analyst approving every state-changing action. **This system never executes
remediation. It only proposes.**

## Architecture

```
                        ┌──────────────────────┐
                        │  Orchestrator/        │
                        │  Supervisor (LangGraph│
                        │  StateGraph)          │
                        └──────────┬────────────┘
      dispatch, merge findings, dedupe, correlate, finalize severity, report
   ┌──────────┬──────────────┬───────────────┬──────────────┬────────────┐
   ▼          ▼              ▼               ▼              ▼
┌────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐
│  Log   │ │  Threat  │ │Vulnerability │ │ Incident  │ │   Policy     │
│Monitor │ │  Intel   │ │  Scanner     │ │ Response  │ │  Checker     │
└────────┘ └──────────┘ └──────────────┘ └───────────┘ └──────────────┘
        shared Finding objects → SQLite Findings Store → Report Builder
```

Execution order (see `orchestrator/graph.py`): `validate` → (`log_monitor`
∥ `vuln_scanner`, run in parallel as a LangGraph fan-out) → `threat_intel`
(enriches both branches' output) → `supervisor_merge` (dedupe/correlate/
finalize severity) → `incident_response` → `policy_checker` → report.

### Key build decisions (this is a hackathon-scoped build)

| Placeholder in the original spec | Decision made |
|---|---|
| Agent framework | **LangGraph** `StateGraph` — explicit nodes/edges make the fan-out/fan-in and fail-safe behavior inspectable |
| Message bus / state | **No external bus.** Handoff between agents in one run is plain in-process Python (LangGraph state); durable state is a local **SQLite** findings store (`reports/findings.db`) — zero external services, `make demo` just works |
| Code/dependency/container scanners | **Real** — wraps `semgrep`, `bandit`, `pip-audit`, `detect-secrets` (gitleaks-compatible), and `trivy` if installed (documented stub interface otherwise) |
| External threat-intel feeds (NVD/OSV/GitHub Advisory/CISA KEV) | **Stubbed** behind a documented `ThreatFeed` interface with canned, real-CVE fixture data (`agents/threat_intel/fixtures/threat_feed_fixtures.json`) — deterministic, offline, no API keys required. Swap in a real feed implementation with zero other code changes. |
| LLM for reasoning agents | **Pluggable** (`tools/llm_client.py`): uses `OPENAI_API_KEY` when set, otherwise falls back to a deterministic `MockLLM` so the whole pipeline runs with zero setup |
| Compliance framework | **NIST CSF 2.0**, a representative 10-control subset across all 6 functions (`agents/policy_checker/controls_nist_csf.py`) — clearly labeled as a subset, never implying full-catalog coverage |
| Interfaces | CLI (`cli.py`, `make demo`) **and** a small FastAPI web UI/REST API (`webui/`) with `/scan /status /findings /report` plus a server-rendered dashboard |
| Deployment | Single `docker-compose.yml`. **Deviation from the original "one container per agent" ask:** because there's no message bus, agents are Python modules called in-process by the orchestrator inside one container — splitting them into separate containers would require introducing Redis/RPC purely for the sake of container-per-agent, which contradicts the "no message bus" hackathon-scope decision above. The compose file ships an `app` service (web UI) and a `demo` one-shot service instead. |

## Guardrails (hard requirements — see spec §8)

- **Read-only by default.** No agent executes remediation, a config change, a
  container restart, or a firewall edit. Every `Finding`/`IncidentStep` is a
  proposal (`requires_human_approval: true` is enforced end to end).
- **Scope enforcement.** Active API scanning requires `--allow-active` AND
  the target must be in `target_allowlist`; the orchestrator refuses
  (`orchestrator: partial`) and never crashes.
- **Evidence or it didn't happen.** Every finding cites raw evidence lines;
  every external claim (CVE data, IOC reputation) carries a source URL —
  real or a clearly labeled `stub://` fixture id.
- **Secret hygiene.** `tools/redact.py` strips credentials/tokens/PII from
  every evidence snippet before it is stored, reported, or sent to the LLM.
- **Determinism where possible.** Scanners/rules produce findings; the LLM
  only explains, correlates, prioritizes, and writes plans — it never
  invents a CVE, a CVSS score, or a detection.
- **Auditability.** Every run writes a full JSONL audit log (inputs, tool
  calls, agent outputs, timings) to `reports/run_logs/<run_id>.jsonl`.
- **Fail safe.** If an agent raises, it's marked `failed` in `agent_status`
  and the run still produces a partial report (see `test_orchestrator_e2e.py`).

## Repo layout

```
contracts/          Shared Pydantic models every agent speaks (Finding, ScanReport, ...)
agents/<name>/       One agent per spec §5: system_prompt.md, tool wrappers, agent.py
orchestrator/        LangGraph StateGraph, supervisor (dedupe/correlate/severity), report builder
tools/               Cross-cutting: LLM client, findings store (SQLite), redaction, audit log
webui/               FastAPI REST API + server-rendered dashboard
demo/                Seeded scenario: brute-force logs, vulnerable deps, Dockerfile misconfig
fixtures/            Small, isolated fixtures used by unit tests
tests/               pytest suite (29 tests) — per-agent + full pipeline
reports/             SQLite findings.db, per-run audit logs, sample ScanReport (json + md)
```

## Setup

```bash
pip install -r requirements.txt
# optional — enables real LLM output instead of the deterministic mock:
export OPENAI_API_KEY=sk-...
```

## Run the demo

```bash
make demo         # runs the seeded scenario end-to-end, writes reports/sample_scan_report.{json,md}
make test         # 29 pytest tests
make run          # starts the web UI at http://localhost:8000
```

Or with Docker:

```bash
docker compose run --rm demo    # one-shot demo run
docker compose up app           # web UI at http://localhost:8000
```

Or via the CLI directly:

```bash
python cli.py scan --repo demo/sample_repo \
  --logs demo/logs/auth.log,demo/logs/access.log,demo/logs/app.json.log \
  --openapi demo/sample_repo/openapi.json
python cli.py list-runs
python cli.py show-report <run_id>
```

## What the demo scenario proves

`demo/logs/` seeds an SSH brute-force from `203.0.113.77` (12 failed logins,
detected as MITRE ATT&CK **T1110**), a path-scan, SQLi/XSS probes, a
data-exfil volume spike, and C2-beacon-like periodic traffic.
`demo/sample_repo/` seeds a real vulnerable dependency (`Flask==0.12`,
matched by `pip-audit` to **CVE-2019-1010083**, enriched with CVSS 6.5 via
the stub threat feed), `PyYAML==5.3.1` (**CVE-2020-14343**, CVSS 9.8, flagged
**KEV** — this one gets bumped to `critical`), a hardcoded AWS key + SQL/OS
command injection/unsafe deserialization in `app.py`, and a misconfigured
`Dockerfile` (root user, `:latest` tag, a baked-in secret).

Running it produces 27 findings, 26 incident plans (every finding at
high+/confidence≥0.7 gets a Contain→Eradicate→Recover→Post-incident plan),
and a NIST CSF 2.0 compliance report with several `Not Met` controls tied
back to the specific findings that caused them.

## How to add a new agent

1. `mkdir agents/my_agent/`, add `system_prompt.md`, `agent.py`, and any tool
   wrappers (keep deterministic tool logic separate from LLM calls, as in
   every existing agent).
2. Consume/produce only `contracts.Finding` (or `IncidentPlan` /
   `ComplianceReport` if you're building something report-shaped) — that's
   the only contract the orchestrator understands.
3. Wire it into `orchestrator/graph.py`: add a node, add edges, and — if it
   can fail independently — wrap its body in try/except and set
   `agent_status["my_agent"]` like every other node does.
4. Add fixtures under `fixtures/` and tests under `tests/test_my_agent.py`
   mirroring the existing per-agent test files.

## Limitations

- This is a **decision-support tool, not an autonomous remediation system.**
  Nothing here changes a firewall rule, restarts a service, or rotates a
  credential — a human must act on every proposal.
- The compliance control catalog is a **representative subset** (10 of
  NIST CSF 2.0's full control set), clearly labeled as such in every report.
- External threat-intel feeds are stubbed with fixture data for demo
  determinism — see the table above for how to point `ThreatFeed` at a real
  backend.
- Container image scanning falls back to a documented stub when `trivy`
  isn't installed; the Dockerfile linter (`lint_dockerfile`) is the
  always-available complement that doesn't need a built image.
- Active API scanning is intentionally minimal (passive header checks) and
  gated by an explicit allowlist — this is not a penetration-testing tool.
