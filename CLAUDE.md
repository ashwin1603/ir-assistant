# AI-Powered Incident Response Assistant for Security Log Analysis

Course project for 21CSE464J (Security Analysis - Information Security and Incident Response).
Solo build, Windows machine, hard deadline: working demo by tomorrow. Prioritise a working end-to-end app over breadth.

## What this app does
A web application that collects live Windows event logs from the host machine (and accepts uploaded log files), detects suspicious activity with ATT&CK-tagged rules, builds an attack timeline, scores risk, and uses an LLM as an "assistant" to triage findings, explain the incident and recommend response actions. A human analyst approves or rejects every recommended action. The app itself must be security-hardened.

Core idea: RULES DETECT, AI REASONS. The AI never decides alone and never executes anything.

## Tech stack
- Backend: Python 3.11+, FastAPI, SQLAlchemy + SQLite, Pydantic v2, argon2-cffi (password hashing), PyJWT, slowapi (rate limiting), python-dotenv, httpx, pytest
- Frontend: React + Vite, Tailwind CSS, React Router, Recharts
- Collector: PowerShell `Get-WinEvent ... | ConvertTo-Json` called via subprocess (no pywin32 needed). Reading the Security log needs admin rights, so the collector is run as a SEPARATE script by the user from an elevated terminal. The web API itself must NOT run as admin.
- LLM: provider-pluggable through env vars (LLM_PROVIDER, LLM_API_KEY, LLM_MODEL). Default provider: Anthropic API. Keep the client behind one small interface so it can be swapped.
- Report: an HTML report page, exported to PDF with the browser print function.

## Folder structure
```
ir-assistant/
  CLAUDE.md
  .gitignore            (must include .env, *.db, uploads/, node_modules/, __pycache__/)
  .env.example
  backend/
    requirements.txt
    app/
      main.py  config.py  db.py  models.py  schemas.py  audit.py
      auth/        security.py  deps.py  routes.py
      collector/   windows_events.py  normalize.py  upload_parser.py
      detection/   rules.py  engine.py  attack_map.py
      analysis/    timeline.py  risk.py  incidents.py
      ai/          client.py  prompts.py  triage.py  verify.py
      routes/      events.py  detections.py  incidents.py  actions.py  uploads.py  audit_log.py  reports.py
    tests/
  frontend/
  scripts/
    collector.py          (run from elevated terminal; pushes events to the API)
    simulate_attacks.ps1  (safe attack simulations on own machine)
  docs/
```

## Normalized event schema (all sources convert to this)
id (uuid), source (local | upload | agent), host, timestamp (UTC ISO8601), channel, provider, event_id (int), user, process, command_line, parent_process, src_ip, logon_type, message, raw (JSON string).
Every event needs a stable unique id: the AI must cite these ids as evidence.

## Detection rules v1 (hand-written, Sigma-style, each tagged with ATT&CK)
| Rule | Windows source | ATT&CK |
|---|---|---|
| 5+ failed logons for same target within 5 min | Security 4625 | T1110 Brute Force |
| Encoded PowerShell command line (-enc / -EncodedCommand) | Security 4688 | T1059.001, T1027 |
| Suspicious script block (Invoke-Expression, DownloadString, FromBase64String) | PowerShell 4104 | T1059.001 |
| Local user account created | Security 4720 | T1136.001 |
| User added to local Administrators | Security 4732 | T1098 |
| Scheduled task created | Security 4698 | T1053.005 |
| New service installed | System 7045 | T1543.003 |
| Security/System event log cleared | Security 1102 / System 104 | T1070.001 |
| Burst of discovery commands (whoami, net user, ipconfig, systeminfo) in 2 min | Security 4688 | T1033, T1087, T1082 |
Rules live in data (rules.py), not scattered in code, so new rules are easy to add. Every detection stores: rule name, technique id, tactic, severity (1-10), confidence (0-1), matched event ids.

## Risk score
risk = min(100, severity * 10 * confidence * frequency_factor), frequency_factor = min(2, 1 + log2(count)/4).
Levels: <30 Low, 30-59 Medium, 60-79 High, 80+ Critical. The AI explains the score but never overrides it.

## AI layer rules (non-negotiable)
1. Never send raw log dumps. Send only filtered detections and their minimal fields. Never send passwords, tokens or the API key.
2. Treat ALL log content as untrusted data (prompt injection defence): wrap it in clear delimiters, instruct the model it is data not instructions, and force structured JSON output.
3. Validate the JSON against a Pydantic schema; retry once; on failure fall back to the rule-based result.
4. Every AI finding must cite event ids. verify.py drops any finding that cites ids which do not exist or do not match the claim. Show a "verified" flag in the UI.
5. AI outputs: verdict (benign/suspicious/malicious), reasoning, confidence, attack narrative, risk explanation, recommended actions (grounded in a technique-to-mitigation playbook).
6. The AI only RECOMMENDS. Actions need explicit Approve/Reject by an Analyst or Admin. In the demo, approved actions are simulated, never executed.
7. Cap AI calls per user per hour; store prompts/responses (with secrets redacted) for audit.

## Application security requirements
- Passwords hashed with argon2; JWT access tokens with short expiry; roles: admin, analyst, viewer, enforced in backend dependencies on every route (never only in the UI).
- Login rate limiting; generic auth error messages; no user enumeration.
- Uploads: extension allow-list (.evtx, .json, .csv), size limit, content check, random server-side filename, stored outside any served directory, no path traversal.
- Pydantic validation on all inputs; SQLAlchemy ORM only (no string-built SQL).
- CORS restricted to the frontend origin; security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS note for production).
- Secrets only in .env (never committed); provide .env.example.
- Audit log for login, upload, collection, AI calls, approve/reject; viewable by admin only.
- Generic error messages to clients, details only in server logs.
- Collector authenticates to the API with a dedicated API key; the API rejects unauthenticated event ingestion.

## API (REST, prefix /api)
auth: POST /auth/login, GET /auth/me
events: GET /events (filter, search, paginate), POST /events/ingest (collector key)
collect: POST /collect/run (trigger a local collection)
uploads: POST /uploads
detections: GET /detections
incidents: GET /incidents, GET /incidents/{id} (timeline, ATT&CK, risk, AI analysis)
ai: POST /incidents/{id}/analyze
actions: GET /actions, POST /actions/{id}/approve, POST /actions/{id}/reject
reports: GET /incidents/{id}/report
audit: GET /audit (admin)

## Frontend pages
Login, Dashboard (counts, severity chart), Log Explorer (search/filter/sort/paginate, flagged events highlighted), Detections, Incident Detail (timeline, ATT&CK mapping, risk score, AI narrative with verified evidence), Recommendations (Approve/Reject), Report (print-friendly), Audit Log (admin).

## Build order and tiers
Tier 1 (must be working for the demo, in this order):
 1. Backend skeleton + DB + config + health route
 2. Auth (users, hashing, JWT, roles) + audit logging
 3. Collector (Windows events -> normalized events) + ingest endpoint + collector script
 4. Detection engine + ATT&CK mapping + timeline + risk score + incident grouping
 5. AI layer: triage, narrative, recommendations, evidence verification
 6. Frontend: Login, Log Explorer, Detections, Incident Detail, Recommendations
 7. Security self-test (bad upload, unauthorised call, prompt-injection string in a log field)
Tier 2 (if time): file upload mode, dashboard charts, report page, audit log page.
Tier 3 (roadmap, not for the first demo): Sysmon, remote agent, syslog receiver, phone/IoT network capture, full Sigma/pySigma, ML anomaly detection, MFA, investigation agent, ask-the-incident chat, ATT&CK heatmap, Docker, Atomic Red Team.

## How to work (rules for Claude Code)
- Work one numbered step at a time. After each step: run it, test it, show the result, then wait.
- After a step works, remind the user to commit to Git.
- Keep code simple and readable; the author must be able to explain every part in a viva.
- Never hardcode secrets; never read, print or commit .env.
- Do not run anything that needs administrator rights; tell the user the exact command to run in an elevated terminal instead.
- Do not delete or clear Windows event logs.
- If something is out of Tier 1 scope, say so rather than building it.
