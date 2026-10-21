# Dependency Vulnerability Scan

Date: 2026-10-21

## Tools
| Part | Tool | Scope |
|---|---|---|
| Backend | pip-audit 2.10.1 (installed in `backend/.venv`) | every package in the venv (Python 3.14) |
| Frontend | npm audit (npm 11.13.0) | `frontend/package-lock.json`, 95 packages |

## Findings
| Part | Vulnerabilities | Severity |
|---|---|---|
| Backend | 0 ("No known vulnerabilities found") | none |
| Frontend | 0 ("found 0 vulnerabilities") | none |

No CVE fixes were needed.

## Upgrades applied (patch-level only, no major bumps)
| Package | From | To | Why |
|---|---|---|---|
| fastapi | 0.156.3 | 0.156.8 | latest patch release |
| vite (dev) | 8.3.4 | 8.3.5 | latest patch release, within existing semver range |

## Verification after upgrade
- pip-audit: 0 vulnerabilities
- npm audit: 0 vulnerabilities
- Backend tests: 123 passed (`pytest -q`)
- Frontend: `npm run build` succeeds

## How to re-run
```
cd backend && .venv\Scripts\python -m pip_audit
cd frontend && npm audit
```

## Note
`requirements.txt` now pins every direct dependency to the scanned version (`==`), so a
fresh install matches what was audited. Frontend versions are locked by `package-lock.json`.
