# IR Assistant - Handoff

## Purpose and architecture
An AI-assisted incident response web app for Windows security logs (course project, 21CSE464J). A collector reads Windows event logs via PowerShell `Get-WinEvent` (or the user uploads `.evtx/.json/.csv` files); events are normalized into one schema and stored in SQLite. A rule engine (YAML Sigma-style rules, network rules, threat-intel matches, plus an ML anomaly layer) raises ATT&CK-tagged detections, which are grouped into incidents with a timeline, attack graph and risk score. A local LLM (Ollama) or a deterministic template provider then explains each incident and recommends actions, citing event ids that `verify.py` checks against the evidence. **Rules detect, AI reasons, humans decide**: every action needs Analyst/Admin approval and is only simulated. Stack: FastAPI + SQLAlchemy + SQLite backend (`backend/`), React + Vite + Tailwind frontend (`frontend/`), helper scripts in `scripts/`. Project rules and design: [CLAUDE.md](CLAUDE.md); results and notes: [docs/](docs/).

## Status

### Done
- Live Windows event collection (collector script, `--watch`) and secure file upload (.evtx/.json/.csv)
- Detection: 18 YAML rules + allowlist, 5 network rules, threat-intel matches; Sigma rule import; custom rule editor (admin)
- ML anomaly detection (numpy isolation forest) + Anomalies page
- ATT&CK matrix and technique pages
- Incidents with timeline, attack graph, risk score; status + notes
- Local-AI analysis (Ollama) with evidence verification; incident chat; investigation assistant
- Recommendations with Approve/Reject (simulated only)
- Per-incident IOC export and review-only response scripts; reports (print layout, versions)
- Local threat intel; Devices and Network pages; live updates over `GET /api/stream`; notification bell; demo mode
- Roles (admin/analyst/viewer) + permission matrix, viewer redaction, step-up auth, optional TOTP MFA
- Audit log (admin)
- Performance: SQLite WAL, cached detection runs
- Glass UI, severity scale, command palette, drawers, table tools + CSV export
- ~395 backend tests; security self-test; validation; method comparison; dependency scan (see `docs/`)

### TODO
| Task | Owner | Status |
|---|---|---|
| Security: login lockout with backoff | | |
| Security: server-side logout / token revocation | | |
| Security: download/export quotas + anomaly alert | | |
| Security: disable `/docs` and `/openapi.json` outside dev | | |
| Security: tamper-evident hash-chained audit log | | |
| Encryption: MFA secret at rest | | |
| Encryption: uploads at rest + delete after parse | | |
| Encryption: exports | | |
| Rotate JWT secret, collector key, admin password (they appeared in a screenshot) | | |
| README | | |
| Architecture doc | | |
| Demo script | | |
| Slides + screenshots | | |
| 2 rehearsals + clean-restart test | | |
| Optional: OWASP ZAP scan (run on a COPY of the DB) | | |
| Optional: Atomic Red Team (Windows VM only) | | |
| Optional: syslog receiver | | |
| Optional: device manager add-by-IP | | |
| Optional: incremental detection | | |
| Optional: Docker (risky) | | |
| Future work: Sysmon, remote agent, phone/IoT capture | | |

## Prerequisites
Windows 10/11 with winget, PowerShell 5.1+. `setup.ps1` installs anything missing: Git, Python 3.14.4, Node.js 24.16.0 LTS, Ollama (≈2 GB for the `qwen2.5:3b` model). Live collection needs admin rights and Windows auditing.

## Quick start
```powershell
git clone <repo-url> ir-assistant
cd ir-assistant
powershell -ExecutionPolicy Bypass -File .\setup.ps1     # installs, creates backend\.env with random secrets
powershell -ExecutionPolicy Bypass -File .\run.ps1       # opens backend + frontend windows
```
Open http://localhost:5173 and log in as `admin` with the password from `backend\.env` (`ADMIN_PASSWORD`). Stop with `.\stop.ps1`. Verify an install without changing anything: `setup.ps1 -Check`.

For live collection, enable auditing once from an **elevated** terminal: `powershell -ExecutionPolicy Bypass -File .\setup.ps1 -EnableAuditing`. For local AI set `LLM_PROVIDER=ollama` in `backend\.env` (default `template` needs no model).

## Demo data
- Seed scripts need the backend running: `backend\.venv\Scripts\python.exe scripts\seed_simulated_events.py` (and `seed_simulated_network.py`). `--wipe` removes simulated events. Simulated data is tagged `source=simulated` on hosts `SIM-WS01` (events) and `SIM-NET01` (network).
- The collector (`scripts\collector.py`) needs an elevated terminal and Windows auditing. Live collection is Windows-only; other OSes can use uploads and seeds.
- Threat-intel demo rows are seeded at backend startup.
- `docs/ground_truth.json` describes the original author's machine; it will not match yours.

## Tests
```powershell
cd backend
$env:LLM_PROVIDER = "template"
.venv\Scripts\python.exe -m pytest -q
```
Always use `LLM_PROVIDER=template`; do not run the full suite against Ollama (slow, non-deterministic). Frontend: `cd frontend; npm run build`.

## Pitfalls
- **"An Application Control policy has blocked this file"** on import: SQLAlchemy's compiled extension is blocked. `setup.ps1` offers the pure-Python reinstall; details in [docs/windows_setup.md](docs/windows_setup.md).
- **"database is locked"**: too many tabs plus the collector writing at once. Close extra tabs, retry.
- **Ports 5173/8000 held by leftovers**: `run.ps1` frees them (python/node only). CORS allows only `http://localhost:5173`; use that exact URL.
- **Backend hangs on "Shutting down"**: close that terminal tab.
- **Never pip/npm install new packages without a dry-run** (`pip install --dry-run`, `npm install --dry-run`), and pin anything you add.
- **Don't run `collector.py --network` in demos.**
- The collector needs admin; the web API must **not** run as admin.
- Running the tests rewrites `docs/security_results.md`; undo with `git restore docs/security_results.md` unless you mean to update it.
- **Never commit** `.env`, `*.db`, `llm_cache*`, `backend/rules/custom`, `backend/rules/imported`, `uploads`.

## Contributor rules
- One branch per task, merged through a PR.
- Tests for every change.
- Every new route goes into the permissions table (`backend/app/auth/permissions.py`, checked by `tests/test_permissions_matrix.py`).
- Never log secrets.
- No paid APIs.

## Security notes and known limitations
- HTTP on localhost only; production would need HTTPS + HSTS.
- TOTP MFA secret is stored unencrypted until the encryption task is done.
- Simulated data is labelled as such; it is not real attack telemetry.
- Small evaluation sample; the ML anomaly layer is weak and supplementary.
- The AI never decides or executes anything: rules detect, AI explains, an analyst approves, actions are simulated.
