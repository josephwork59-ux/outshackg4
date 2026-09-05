# CyberGuard - multi-agent cybersecurity AI system

A small, dependency-free reference implementation of the system described in
[`../cybersecurity-ai-agent-prompt.md`](../cybersecurity-ai-agent-prompt.md):
five specialized agents coordinated by an orchestrator that monitor logs, find
security issues, correlate them with known threats, check compliance, and
produce remediation plans.

> **This is decision support, not an autonomous remediation system.** No agent
> executes a state-changing action. Every remediation is a proposal, and every
> state-changing plan step is flagged `requires_human_approval`.

---

## Architecture

```
                        +---------------------+
                        |   Orchestrator /    |
                        |   Supervisor        |
                        +----------+----------+
   dispatch -> enrich -> deduplicate -> correlate -> score -> plan -> report
   +----------+--------------+---------------+--------------+---------------+
   v          v              v               v              v
+--------+ +----------+ +--------------+ +-----------+ +--------------+
|  Log   | |  Threat  | |Vulnerability | | Incident  | |   Policy     |
|Monitor | |  Intel   | |  Scanner     | | Response  | |  Checker     |
+--------+ +----------+ +--------------+ +-----------+ +--------------+
        shared Finding objects  ->  correlate/score  ->  Report Builder
                                                          (JSON + Markdown + console)
```

| Agent | Job | Key output |
| --- | --- | --- |
| **Log Monitor** | Detect unusual activity / attacks in system & network logs | brute-force, web-injection probes, sudo abuse, log tampering - each with cited log lines + MITRE ATT&CK id |
| **Threat Intelligence** | Look up CVEs / IOCs, decide if *this* system is affected | CVSS / EPSS / KEV enrichment, "affected: yes/no/uncertain" + reasoning, known-malicious-IP findings |
| **Vulnerability Scanner** | Scan code, dependencies, Dockerfiles, images | one finding per weakness with `file:line`, CWE/OWASP, fixed version, redacted proof |
| **Incident Response** | Turn a confirmed finding/cluster into a plan | phased Contain -> Eradicate -> Recover -> Post-incident plan, NIST SP 800-61, approval gates |
| **Policy Checker** | Map findings to NIST CSF / SOC 2 / ISO 27001 | per-control Met/Partial/Not Met/Not Assessed, gap backlog, finding->control matrix |

The **Orchestrator** runs Log Monitor + Vulnerability Scanner in parallel, feeds
their output to Threat Intelligence, then deduplicates, correlates (shared IP /
shared CVE), finalizes severity, generates incident plans for confirmed/high
clusters, runs the Policy Checker over everything, and builds the report.

---

## Quick start

```bash
cd cyberguard
make demo      # run the seeded scenario end-to-end + check acceptance criteria
make test      # unit tests (needs: pip install pytest)
make scan      # same scan via the CLI, writes reports/<run>.json + .md
make lint      # byte-compile every module (no deps)
```

The core has **no runtime dependencies** (standard library only). `make demo`
runs fully offline and deterministically.

### CLI

```bash
python -m cli scan     --config demo/scenario.json [--out reports/] [--json]
python -m cli report   --report reports/<run>.json      # re-render markdown
python -m cli findings  --report reports/<run>.json --min-severity high
python -m cli status   --report reports/<run>.json
```

`scan` exits `2` when any high/critical finding exists (useful as a CI gate),
`0` otherwise.

### Scan target

`demo/scenario.json` is a `ScanTarget`:

```json
{
  "name": "acme-payments-api (demo)",
  "log_sources": [{"path": "demo/env/var/log/auth.log", "format": "syslog"}],
  "repo_path": "demo/env/app",
  "dockerfiles": ["demo/env/app/Dockerfile"],
  "images": [],
  "api_endpoints": ["https://api.acme.example/v1/pay"],
  "framework": "NIST_CSF",
  "asset_criticality": "high",
  "exposure": "external",
  "allowlist": [],
  "allow_active": false
}
```

---

## The demo scenario

`demo/env/` is a seeded environment containing:

- **`var/log/auth.log`** - a 8-attempt SSH brute-force from `203.0.113.66`, plus sudo abuse.
- **`var/log/nginx/access.log`** - `sqlmap` SQLi, an XSS probe, and a path-traversal attempt.
- **`app/requirements.txt`** - `PyYAML==5.3.1` (CVE-2020-14343) and `Jinja2==2.10` (CVE-2019-10906).
- **`app/Dockerfile`** - `:latest` base, runs as root, `ADD <url>`, a secret in `ENV`.
- **`app/settings.py`** - a hardcoded AWS key.

`make demo` asserts the acceptance criteria from the prompt: a finding from each
scanning agent, brute-force with an ATT&CK id + evidence, a dependency matched to
a real CVE with a fixed version and a KEV/EPSS note, a fully-phased incident plan
with approval gates, a compliance report with failing controls and a
finding->control matrix, and that nothing state-changing runs ungated.

A sample rendered report is in [`reports/`](reports/).

---

## Guardrails

- **Read-only by default.** No remediation, restart, or firewall change is executed. Plans are proposals; state-changing steps carry `requires_human_approval: true`.
- **Scope enforcement.** Active API testing requires `allow_active: true` **and** each host on `allowlist`. This build ships no active network prober - it must be added deliberately.
- **Evidence or it didn't happen.** Every finding cites raw (redacted) evidence; every external claim carries a source URL.
- **Secret hygiene.** [`tools/redaction.py`](tools/redaction.py) strips credentials/PII from evidence, logs, and anything sent to the LLM. IP addresses are kept (needed as evidence).
- **Determinism.** Rules and scanners produce the findings. The LLM only explains, correlates, and drafts prose - it never invents a CVE or a severity.
- **Fail safe.** An agent that errors is marked `failed` in `agent_status`; the run still produces a partial report. A partially-unreadable log source degrades to `partial`.
- **Auditability.** Every severity change is recorded in `finding.enrichment.severity_adjustment`; the full report (inputs, agent notes, correlations) is written as JSON.

---

## LLM backend

`llm/` is pluggable. Default is `DeterministicLLM` (offline, template-driven).
To use `claude-sonnet-5` for the prose (advisory summaries, executive summary,
incident comms):

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
export CYBERGUARD_LLM=claude
```

If the package or key is missing it logs a note and falls back to deterministic -
a run never breaks on LLM availability.

---

## Real scanners

[`tools/external.py`](tools/external.py) shells out to real tools **when they are
on `PATH`**: `semgrep`, `bandit`, `pip-audit`, `trivy`, `hadolint`. When a tool
is absent the agent degrades to its built-in checks and reports status
`partial` - a missing tool is never a run failure. Install what you want:

```bash
pip install semgrep bandit pip-audit      # trivy / hadolint: see their docs
```

The bundled `data/cve_db.json` and `data/ioc_blocklist.json` are an **offline
sample**, not a live feed. For production, implement
`agents.threat_intel.FeedProvider` against NVD / OSV / a commercial feed and pass
it to `ThreatIntelAgent`.

---

## Adding an agent

1. Subclass `agents.base.Agent`, set `name` / `role` / `system_prompt`, implement `_run(target, context) -> AgentResult`.
2. Return `Finding` objects using the shared contract (`contracts/models.py`). Give each a stable `signature` so the orchestrator can dedupe/correlate it.
3. Wire it into `orchestrator/orchestrator.py` (and, if it needs its own worker, `_AGENTS` in `tools/worker.py`).
4. Add fixtures under `tests/fixtures/` and a `tests/test_<agent>.py`.

---

## Layout

```
cyberguard/
  contracts/        Finding, ScanReport, IncidentPlan, ComplianceReport, ScanTarget
  agents/           the five agents + base class (each carries its system prompt)
  orchestrator/     supervisor, correlation, severity scoring, report builder
  llm/              pluggable LLM layer (deterministic default, claude optional)
  tools/            redaction, version compare, log parsing, external-scanner wrappers, worker
  data/             offline sample CVE/IOC feed + framework control subsets
  demo/             seeded environment + run_demo.py (acceptance checks)
  tests/            pytest suite + fixtures
  cli.py            scan / report / findings / status
  docker-compose.yml + Dockerfile   illustrative one-container-per-agent topology
```

## Non-goals

Autonomous patching or blocking; full commercial threat-feed integration;
exhaustive control catalogs (a labelled subset is used); an active network/API
prober (must be added deliberately, behind the allowlist).
