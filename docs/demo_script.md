# Demo script (8–10 minutes)

## Before presenting

1. On the presentation machine, clone the repository and follow `README.md`. Run `setup.ps1 -Check`, then `setup.ps1`; keep `.env` private and confirm it contains a stable `DATA_ENCRYPTION_KEY`.
2. Rotate that machine's previously exposed JWT secret, collector API key, and admin password. Do not put values in slides or screenshots.
3. Start the app with `run.ps1`, open <http://localhost:5173>, and use the local admin credentials from `backend/.env`.
4. From a second terminal, seed safe synthetic events:

   ```powershell
   backend\.venv\Scripts\python.exe scripts\seed_simulated_events.py
   backend\.venv\Scripts\python.exe scripts\seed_simulated_network.py
   ```

5. Confirm the seeded host names are `SIM-WS01` and `SIM-NET01`. They are synthetic examples, not evidence of a real compromise.

## Presentation flow

### 1. Problem and scope (45 seconds)

Explain that analysts spend time sorting Windows and network logs. This project supports on-demand investigation: collect or upload records, normalize them, detect suspicious patterns, group related findings, and prepare evidence-backed triage. It is not a production SIEM or always-on streaming service.

### 2. Dashboard and log explorer (1 minute)

Show dashboard counts and severity distribution. Open Log Explorer and filter to `SIM-WS01`. Point out the simulated label and normalized host, timestamp, process, and event details. If showing CSV export, note that results are capped, viewer content is redacted, and the per-user rolling quota is enforced.

### 3. Detections and ATT&CK (1–2 minutes)

Open Detections and show examples such as encoded PowerShell, service creation, or log clearing. Open an ATT&CK technique page and explain the relationship between detection rules and technique IDs. Emphasize that rule hits and their matched event IDs are the evidence.

### 4. Incident investigation (2 minutes)

Open an incident and walk through the ordered timeline, attack graph, severity/risk score, and evidence references. If the local Ollama model is unavailable, template mode still provides deterministic explanations. Explain that AI summarizes and recommends; rules determine the detections and analysts remain in control.

### 5. Human-approved response and report (1 minute)

Show recommendations and the approve/reject controls. State clearly that approval changes application state only: response scripts are generated for review and are never executed. Open the print-friendly report and show the incident summary, timeline, ATT&CK mapping, and recommended actions.

### 6. Security controls (1–2 minutes)

- Show the admin Audit Log and its integrity verification result.
- Explain roles and viewer redaction; access is enforced in backend route permissions.
- Show Settings or MFA status if time permits. Explain server-side logout revocation, login backoff, and download/export quotas.
- If demonstrating the upload flow, use a small synthetic file only; do not upload real organizational logs during a classroom presentation.

### 7. Close (30 seconds)

Summarize the end-to-end workflow and state the limitations honestly: small evaluation sample, supplementary ML anomaly scoring, local-only HTTP demo, and no production streaming or automated response execution.

## Cleanup

Stop with `stop.ps1`. Synthetic records may be removed with the documented `--wipe` commands; do so only if the team wants a clean demo database. Do not delete or reset the database during a live demo, and do not run the collector with `--network` in a presentation.

## Rehearsal checklist

- [ ] Run through the flow twice on a clean restart.
- [ ] Confirm app URLs, local login, and demo seed commands on the actual presentation machine.
- [ ] Capture screenshots only after redaction and simulated labels are visible; exclude `.env`, tokens, and real host/user data.
- [ ] Have a fallback ready: pre-seeded synthetic data and `LLM_PROVIDER=template`.
- [ ] Record actual demo duration and remove any step that consistently stalls.
