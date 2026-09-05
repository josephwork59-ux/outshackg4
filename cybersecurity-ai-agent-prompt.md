# Structured Prompt — Build a Multi-Agent Cybersecurity AI System

Use this prompt to instruct a coding agent (Claude Code, Cursor, etc.) to design and
build the system. Fill in the `<<...>>` placeholders before running.

---

## 1. Role

You are a senior security-platform engineer. Build an **AI-powered cybersecurity
system composed of multiple cooperating agents** that continuously monitors logs,
identifies security issues, correlates them with known threats, checks compliance,
and produces actionable remediation plans — with a human analyst in the loop for
any state-changing action.

## 2. What the system must demonstrate

A working multi-agent pipeline where specialized agents each own one job, share a
common findings format, and are coordinated by an orchestrator. Given a sample
environment (logs + source repo + running services), the system should:

1. Detect unusual or malicious activity from logs.
2. Enrich detections with threat-intelligence context (CVEs, advisories, IOCs).
3. Scan code / APIs / container images for vulnerabilities.
4. Map findings to a compliance framework and list the gaps.
5. Emit a prioritized incident-response plan for each confirmed issue.

## 3. Target stack (adjust if the user specifies otherwise)

- **Language:** `<<Python 3.11+>>`
- **Agent framework:** `<<Claude Agent SDK / LangGraph / CrewAI / custom asyncio>>`
- **LLM:** `claude-sonnet-5` for reasoning agents, a smaller model for high-volume
  log triage
- **Message bus / state:** `<<Redis / SQLite / in-memory queue>>`
- **Deployment:** single `docker-compose` stack; one container per agent + orchestrator
- **Interfaces:** CLI + REST API (`/scan`, `/status`, `/findings`, `/report`)

## 4. Architecture

```
                        ┌─────────────────────┐
                        │   Orchestrator /    │
                        │   Supervisor Agent  │
                        └─────────┬───────────┘
      dispatch tasks, merge findings, dedupe, prioritize, report
   ┌──────────┬──────────────┬───────────────┬──────────────┬────────────┐
   ▼          ▼              ▼               ▼              ▼            
┌────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐
│  Log   │ │  Threat  │ │Vulnerability │ │ Incident  │ │   Policy     │
│Monitor │ │  Intel   │ │  Scanner     │ │ Response  │ │  Checker     │
└────────┘ └──────────┘ └──────────────┘ └───────────┘ └──────────────┘
        shared Finding objects  ──►  Findings Store  ──►  Report Builder
```

### Orchestrator / Supervisor Agent
- **Job:** Own the run lifecycle. Accept a scan request, decide which agents to
  invoke and in what order, pass context between them, deduplicate and correlate
  findings, assign final severity/priority, and trigger the report builder.
- **Inputs:** scan target definition (log sources, repo path, image list, framework).
- **Outputs:** consolidated `ScanReport` (see §6), run log, per-agent status.
- **Rules:** never executes remediation; only proposes. Escalates to a human when
  confidence is low or findings conflict.

## 5. Agent specifications

For **each** agent below, produce: (a) a system prompt, (b) the tool/function
signatures it may call, (c) input schema, (d) output as a list of `Finding`
objects, (e) unit tests with fixture data, (f) a short README section.

### 5.1 Log Monitor Agent
- **Purpose:** Read system and network logs and detect unusual activity or attacks.
- **Inputs:** log file paths or a stream (auth.log, syslog, nginx/apache access
  logs, firewall logs, JSON app logs, cloud audit logs).
- **Capabilities / tools:**
  - `tail_logs(source, since)` — pull recent entries
  - `parse_log(line, format)` — normalize to a common event schema
  - `detect_anomalies(events)` — rules + statistical baseline (rate spikes, new
    geo/ASN, off-hours access) and optional LLM pattern review of suspicious clusters
  - Signature checks for: brute force / credential stuffing, port scans, SQLi/XSS
    probes in URLs, privilege escalation, data-exfil volume anomalies, C2 beacon
    periodicity, disabled logging / log tampering
- **Output:** `Finding` per suspicious pattern with raw evidence lines, source IPs,
  timestamps, MITRE ATT&CK technique ID where known, and a confidence score.
- **Constraints:** must cite exact log lines; no destructive parsing; redact
  secrets/PII in evidence snippets.

### 5.2 Threat Intelligence Agent
- **Purpose:** Look up known threats and determine whether this system is affected.
- **Inputs:** software inventory (packages, versions, OS, images), IOCs and IPs
  from the Log Monitor, CVE IDs from the Vulnerability Scanner.
- **Capabilities / tools:**
  - `lookup_cve(id | package, version)` — query NVD / OSV / GitHub Advisory
  - `enrich_ioc(ip | domain | hash)` — reputation, known campaigns (pluggable feed;
    stub allowed with a documented interface)
  - `check_kev(cve_id)` — CISA Known Exploited Vulnerabilities
  - `summarize_advisory(url_or_text)` — LLM summary: affected versions, attack
    vector, patch availability, exploit maturity
- **Output:** `Finding` enrichment records — CVSS, EPSS, KEV flag, exploited-in-wild
  status, "affected: yes/no/uncertain" with reasoning, recommended fixed version.
- **Constraints:** every claim links to a source; mark data as stale if the feed
  timestamp is older than `<<7 days>>`; no unsourced severity assertions.

### 5.3 Vulnerability Scanner Agent
- **Purpose:** Scan code, APIs, and Docker images for security weaknesses.
- **Inputs:** repo path, list of API endpoints / OpenAPI spec, Docker image names
  or Dockerfiles.
- **Capabilities / tools (wrap real scanners; don't reinvent):**
  - Code: `run_semgrep(path)`, `run_bandit(path)` (or language equivalents),
    secret scan (`gitleaks`/`trufflehog`)
  - Dependencies: `run_osv_scanner(lockfiles)` / `npm audit` / `pip-audit`
  - Containers: `run_trivy(image)` — OS packages, app deps, misconfig, secrets
  - APIs: auth/authz checks, missing rate limiting, verbose errors, insecure
    CORS, missing security headers, injection probes against a **non-production**
    target only
  - IaC/config: `run_checkov` / `run_tfsec` if Terraform/K8s present
- **Output:** `Finding` per weakness — file:line or image layer, category (OWASP
  Top 10 / CWE), severity, fixed version or patch, proof snippet, false-positive
  likelihood.
- **Constraints:** read-only against code; active API tests require an explicit
  `--allow-active` flag and a target allowlist; never scan hosts not in scope.

### 5.4 Incident Response Agent
- **Purpose:** Create step-by-step action plans when an issue is found.
- **Inputs:** one confirmed/high-confidence `Finding` or a correlated finding
  cluster from the orchestrator, plus environment context (asset criticality,
  owners, exposure).
- **Capabilities / tools:**
  - `build_plan(finding)` — produce phased actions: **Contain → Eradicate →
    Recover → Post-incident**, each step with owner role, concrete command or
    change, rollback, and verification check
  - `estimate_impact(finding)` — blast radius, data at risk, regulatory exposure
  - `draft_comms(finding)` — internal notification + (if needed) disclosure draft
  - `map_playbook(finding)` — align to NIST SP 800-61 IR lifecycle
- **Output:** `IncidentPlan` — ordered steps, priority (P1–P4), SLA target,
  required approvals, evidence-preservation checklist.
- **Constraints:** proposes only; each state-changing step flagged
  `requires_human_approval: true`; preserve forensic evidence before eradication.

### 5.5 Policy Checker Agent
- **Purpose:** Check the setup against ISO 27001, NIST CSF / 800-53, or SOC 2 and
  show where fixes are needed.
- **Inputs:** framework name + version, system configuration facts, and the full
  findings set from the other agents.
- **Capabilities / tools:**
  - `load_controls(framework)` — control catalog (bundled subset acceptable)
  - `map_finding_to_control(finding)` — link technical findings to control IDs
  - `assess_control(control, evidence)` — status: Met / Partial / Not Met / N/A
    with rationale and the evidence used
  - `gap_report()` — per control: gap description, remediation, effort estimate
- **Output:** `ComplianceReport` — coverage %, table of failing controls,
  prioritized remediation backlog, mapping matrix (finding ↔ control).
- **Constraints:** no compliance "pass" claim without cited evidence; clearly label
  the framework version and which control subset was evaluated.

## 6. Shared data contracts

Define these as typed models (Pydantic/dataclass) and use them everywhere:

```python
Finding:
  id: str                      # stable hash of (agent, target, signature)
  agent: str
  title: str
  description: str
  severity: Literal["critical","high","medium","low","info"]
  confidence: float            # 0..1
  category: str                # CWE / OWASP / ATT&CK / control id
  target: str                  # file:line | image layer | log source | endpoint
  evidence: list[str]          # redacted snippets, always cited
  references: list[str]        # URLs to advisories/docs
  recommended_fix: str
  requires_human_approval: bool
  discovered_at: datetime
  correlated_ids: list[str]    # links to related findings

ScanReport:
  run_id, started_at, finished_at, target_summary
  findings: list[Finding]
  incident_plans: list[IncidentPlan]
  compliance: ComplianceReport
  agent_status: dict[str, "ok|partial|failed"]
  executive_summary: str       # LLM-written, <200 words
```

## 7. Orchestration flow

1. `Orchestrator` receives a scan request and validates scope/allowlist.
2. Run in parallel: `Log Monitor`, `Vulnerability Scanner`.
3. Feed their IOCs/CVEs to `Threat Intelligence`; wait for enrichment.
4. Orchestrator deduplicates, correlates, and finalizes severity
   (base severity × exploit maturity × asset criticality × exposure).
5. For each finding at `high`+ or `confidence ≥ 0.7`, invoke `Incident Response`.
6. Run `Policy Checker` over the full findings set.
7. `Report Builder` emits `ScanReport` as JSON + Markdown + a console summary.
8. Any `requires_human_approval` action is queued, never executed.

## 8. Guardrails (hard requirements)

- **Read-only by default.** No remediation, config change, container restart, or
  firewall edit is executed by an agent. All such actions are proposals.
- **Scope enforcement.** Active scanning only against an explicit target allowlist;
  refuse out-of-scope hosts.
- **Evidence or it didn't happen.** Every finding cites raw evidence and every
  external claim cites a source URL.
- **Secret hygiene.** Redact credentials, tokens, and PII from all evidence and
  logs. Never send secrets to the LLM.
- **Determinism where possible.** Rules/scanners produce the findings; the LLM
  explains, correlates, prioritizes, and writes plans — it does not invent CVEs.
- **Auditability.** Persist a full run log: inputs, tool calls, agent outputs,
  timings, model versions.
- **Fail safe.** If an agent errors, mark it `failed` in `agent_status` and still
  produce a partial report.

## 9. Deliverables

1. Repo layout: `orchestrator/`, `agents/<name>/`, `contracts/`, `tools/`,
   `reports/`, `tests/`, `fixtures/`, `docker-compose.yml`, `README.md`.
2. Each agent: system prompt file, tool wrappers, tests with sample fixtures.
3. A `demo/` scenario: seeded log files with an embedded brute-force + a
   vulnerable dependency + a Dockerfile misconfig, plus `make demo` that runs the
   full pipeline and prints the report.
4. `README.md`: architecture diagram, setup, how to add an agent, guardrails,
   limitations, and a note that this is a decision-support tool, not an autonomous
   remediation system.
5. Sample `ScanReport` (JSON + rendered Markdown) checked into `reports/`.

## 10. Acceptance criteria

- `make demo` completes and produces a `ScanReport` with at least one finding from
  each of Log Monitor, Vulnerability Scanner, and Threat Intelligence.
- The brute-force in the seeded logs is detected with cited log lines and an
  ATT&CK technique ID.
- The vulnerable dependency is matched to a real CVE with a fixed version and a
  KEV/EPSS note.
- At least one `IncidentPlan` with Contain/Eradicate/Recover/Post-incident phases
  and human-approval flags.
- `ComplianceReport` lists failing controls for the chosen framework with a
  finding-to-control mapping.
- No agent performs a state-changing action; all are queued as proposals.
- Unit tests pass; a broken/empty log source yields a partial report, not a crash.

## 11. Out of scope / non-goals

- Autonomous patching or blocking.
- Full commercial threat-feed integration (stub with a documented interface).
- Exhaustive control catalogs (a representative subset is fine, clearly labeled).

---

### How to use this prompt

> Implement the system described above. Start by scaffolding the repo and the
> shared `contracts/` models, then build agents in this order: Log Monitor →
> Vulnerability Scanner → Threat Intelligence → Incident Response → Policy Checker
> → Orchestrator → Report Builder. After each agent, add fixtures and tests and
> run them before moving on. Finish with the `demo/` scenario and `README.md`.
> Ask me before adding any tool that performs an active network scan or a
> state-changing action.
