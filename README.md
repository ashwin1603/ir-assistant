# IR Assistant

AI-assisted incident response for Windows security logs. The application ingests uploaded or locally collected logs, detects suspicious behavior with ATT&CK-tagged rules, groups findings into incidents, and presents a timeline, risk score, evidence, and analyst response recommendations. The AI explains findings; analysts decide what to do. Approved response actions are simulated and are never executed by the app.

## Stack and structure

- **Backend:** Python, FastAPI, SQLAlchemy, SQLite (`backend/app/`)
- **Frontend:** React, Vite, Tailwind CSS (`frontend/`)
- **Collection and demo tools:** PowerShell/Python scripts (`scripts/`)
- **Detection:** YAML rules, network rules, threat-intel matches, and a supplementary Isolation Forest anomaly layer
- **AI:** local Ollama (`qwen2.5:3b`) or deterministic `template` provider

See [the architecture and data flow](docs/architecture.md), [the demo guide](docs/demo_script.md), [the browser slide deck](docs/presentation.html), [credential rotation steps](docs/security_rotation.md), and [the team handoff](HANDOFF.md) for implementation details and remaining work.

## Fresh Windows setup

Prerequisites: Windows 10/11, PowerShell 5.1+, Git, winget, Python 3.14.4, and Node.js 24.16.0 LTS. `setup.ps1` installs missing tools, creates the backend virtual environment, installs pinned Python packages, runs `npm ci`, and creates `backend/.env` with local secrets and a Fernet encryption key. Ollama is optional when using the default `template` provider.

```powershell
git clone <repo-url> ir-assistant
cd ir-assistant
powershell -ExecutionPolicy Bypass -File .\setup.ps1
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Check # optional verification after setup
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

Open <http://localhost:5173>. Sign in as `admin` using the password in `backend/.env` (`ADMIN_PASSWORD`). Stop the app with:

```powershell
powershell -ExecutionPolicy Bypass -File .\stop.ps1
```

Keep `backend/.env` private and out of Git. Back up `DATA_ENCRYPTION_KEY` securely and keep it stable: changing or losing it prevents the app from decrypting stored MFA secrets. Each teammate must use their own local secrets. Rotate the previously exposed JWT secret, collector key, and admin password before sharing or presenting.

For live Windows event collection, enable auditing from an elevated PowerShell as described in [HANDOFF.md](HANDOFF.md). Run the web API as a normal user; only the separate collector needs elevation. On other systems, use uploaded logs or simulated demo data.

## Demo data

Start the backend and frontend with `run.ps1`, then seed synthetic Windows and network events from another terminal:

```powershell
backend\.venv\Scripts\python.exe scripts\seed_simulated_events.py
backend\.venv\Scripts\python.exe scripts\seed_simulated_network.py
```

The records are synthetic, labelled as simulated, and do not execute attacks or contact the listed external IPs. The scripts use the local `COLLECTOR_API_KEY` from `backend/.env` without printing it. See [demo_script.md](docs/demo_script.md) for the guided presentation flow.

## Tests and checks

Backend tests use the deterministic provider and an isolated in-memory test database:

```powershell
cd backend
$env:LLM_PROVIDER = "template"
.venv\Scripts\python.exe -m pytest -q
```

The security self-test rewrites `docs/security_results.md`; review and retain or restore that generated file after running it. Frontend production build:

```powershell
cd frontend
npm run build
```

See `docs/verification_report.md`, `docs/validation_results.md`, and `docs/method_comparison.md` for the prior evaluation. Those are dated results, not a claim that a new run was performed on your machine.

## Important scope and limitations

- Live Windows collection is on-demand/watch mode, not a full streaming SIEM.
- Detection quality and ML evaluation use a small dataset; the anomaly model is supplementary.
- `template` mode is deterministic fallback text, not an LLM. Ollama is local and optional.
- Uploaded EVTX parsing uses a temporary plaintext file which is deleted after parsing. Staged upload files are encrypted and removed.
- Hash-chained audit records detect partial edits and tail deletion using a separately stored chain head. A person who can rewrite the entire database can recompute both; this is not an external immutable archive.
- The application is designed for localhost demonstration, not production deployment. Production use requires deployment hardening, TLS, key management, monitoring, and independent security review.

## Contributing

Use one branch per task and open a pull request. Preserve role permissions and viewer redaction, add every new API route to `backend/app/auth/permissions.py`, add regression tests, and never commit `.env`, databases, uploads, or local custom/imported rules. Follow the detailed rules and outstanding task list in [HANDOFF.md](HANDOFF.md).
