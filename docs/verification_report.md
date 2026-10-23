# Verification report

Date: 2026-10-23. Backend run with `LLM_PROVIDER=template` (no Ollama calls). No packages were
installed, no detection rules were changed or tuned, and the dev database was not modified:
validation scripts ran against a read-only snapshot copy of `backend/ir_assistant.db`.

## Results

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | Full backend test suite | PASS | 320 passed, 0 failed (before the new smoke test). With the smoke test: 323. |
| 2 | Detection validation (`scripts/validate.py` → `validation_results.md`) | PASS | Numbers identical to 2026-10-21; see below. |
| 3 | Method comparison rows from cached LLM verdicts | SKIPPED | Not possible without new LLM calls; see below. `method_comparison.md` left unchanged. |
| 4 | Security self-test (`security_results.md` regenerated) | PASS | 12/12 checks pass. |
| 5 | Dependency scan (`dependency_scan.md`) | PASS with 1 accepted risk | npm: 0. pip-audit: diskcache CVE-2025-69872 (transitive via pySigma, no fix exists). `pip check` clean. |
| 6 | Smoke test, every GET route × admin/analyst/viewer (`tests/test_smoke_all_routes.py`) | PASS | 24 GET routes: no 5xx, no stack traces, role rules hold, every non-public route gives 401 without a token. |
| 7a | No secrets/data in git (`.env`, `*.db`, `uploads/`, `llm_cache*`, `rules/custom`, `rules/imported`, exported samples) | PASS | None tracked. `docs/ground_truth.json` names the lab host (`DESKTOP-M35SOM0`) but no usernames. |
| 7b | `.env` secret values in tracked files | PASS | JWT_SECRET, COLLECTOR_API_KEY, ADMIN_PASSWORD: 0 hits (checked by script; values never printed). |
| 7c | `.env.example` lists every variable `config.py` reads | FIXED → PASS | Was missing `OLLAMA_NUM_PREDICT`, `OLLAMA_NUM_CTX`, `OLLAMA_KEEP_ALIVE`; added. |
| 7d | `requirements.txt` pinned | PASS | Every entry uses `==`; every imported third-party module is listed. |

## What was fixed
- **`.env.example`** was missing three variables that `config.py` reads (the Ollama tuning
  values). They had defaults, so nothing broke, but a new user could not see them. Added with the
  same defaults as `config.py`.
- **New smoke test, first draft:** it listed routes from `app.routes`, which in this FastAPI
  version only exposes `/api/health` (included routers are wrapped). A guard assertion
  (`>= 20 routes`) caught this, so the test was not silently checking nothing. It now reads
  routes from the OpenAPI schema, the same way the existing security self-test does. I checked:
  the self-test was already correct.
- No application bugs were found; no existing test was changed.

## Validation: why the numbers did not shift
Since 2026-10-21 the project gained threat-intel matching, network rules, the custom-rule editor
and Sigma import. The validation results are unchanged (real: recall 9/9, precision 7/8; simulated:
15/15, 0 false positives) because:
- **Network rules** only read `Network`-channel events. The only ones are on the simulated host
  `SIM-NET01`, which is not part of `ground_truth.json`.
- **Threat intel** fires a separate "Known-bad indicator seen" detection on `SIM-WS01` and `SIM-NET01`.
  The simulated validation counts each malicious event as caught by its *expected* rule, so an extra
  detection cannot change it. The real host has no indicator hits.
- **Custom/imported rules:** `backend/rules/custom/` and `backend/rules/imported/` are empty. The DB
  has one `rule_overrides` row, with `enabled=1` and no threshold changes, so it has no effect.
- On the real host, the newer rules' detections (e.g. 3 × "New service installed outside trusted
  paths") fall outside the 10:30-11:20 attack window. Real-host precision only counts detections
  inside the window, so it stays at 7/8. The new rules on `SIM-WS01` fire on the simulated events
  they were written for, which were already counted.

## Method comparison: why it was skipped
`compare_methods.py` was run with a guard that aborts before any LLM call. 57 of the 116 labelled
events had cached verdicts and 59 did not: the simulated events were re-seeded since the cache was
built (new event ids), and the random benign sample is drawn from a larger event table. Updating
only some rows would mix two different labelled sets, so the file was left as is. To refresh it, run
`python scripts/compare_methods.py` with Ollama available (about 59 × 2 new model calls).

## Known limitations
- **HTTP on localhost.** There is no TLS; HSTS is only noted for production. Tokens and passwords
  are sent in clear text on the loopback interface.
- **MFA secrets are stored unencrypted** in SQLite (`users.mfa_secret`). Anyone who can read the DB
  file can generate codes. Recovery codes are argon2-hashed.
- **Simulated data.** `SIM-WS01` / `SIM-NET01` events are synthetic. They are labelled
  `source="simulated"` in the DB and "simulated" in the UI and reports.
- **Small n.** Validation covers 9 real technique instances and 15 simulated events. One event
  changes the percentages a lot.
- **We wrote the rules and the labels.** The rules were written for these exact attacks and
  simulations, so the recall is optimistic. No independent ground truth.
- **ML layer is weak.** Isolation Forest only scores 4688 events, trains on this host's own data
  (including the attack window), and uses a fixed top-5% cut. It is a demo of the idea, not a detector.
- **diskcache advisory** (see `dependency_scan.md`), accepted for the demo.
- The watch collector (`collector.py --watch`) needs an elevated terminal and was not run in this
  pass. Its RecordId XPath filter was checked on the System log.
