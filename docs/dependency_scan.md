# Dependency Vulnerability Scan

Date: 2026-10-23 (previous scan: 2026-10-21)

## Tools
| Part | Tool | Scope |
|---|---|---|
| Backend | pip-audit 2.10.1 (installed in `backend/.venv`) | every package in the venv (Python 3.14.4), and `requirements.txt` on its own |
| Frontend | npm audit (npm 11.13.0) | `frontend/package-lock.json`, 158 packages |

New since the last scan: `pysigma`, `numpy`, `jq`, `google-re2` (plus pySigma's transitive dependencies).

## Findings
| Part | Vulnerabilities | Severity |
|---|---|---|
| Backend | 1 advisory in 1 package: `diskcache 5.6.3`, PYSEC-2026-2447 / CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v | no fix version published |
| Frontend | 0 ("found 0 vulnerabilities") | none |

### diskcache (accepted risk)
- What: diskcache stores values with Python `pickle`. An attacker who can **write to the cache
  directory** can get code execution when the application next reads the cache.
- Why it is here: it is pulled in by `pySigma` (the Sigma rule importer), not used by our code.
- Fix: none available (affects all versions up to 5.6.3, the latest).
- Exposure: the attacker already needs write access to a local directory of the user running the
  API, which is equivalent to local code execution already. The API never exposes the cache
  directory. Accepted for the demo; remove or replace when pySigma or diskcache ships a fix.

## pip check
`pip check`: "No broken requirements found."

## Pinning
`requirements.txt` pins every direct dependency with `==`, including the new ones
(`pysigma==2.0.1`, `numpy==2.5.4`, `jq==1.13.0`, `google-re2==1.1.20251105`), so a fresh install
matches what was audited. Every third-party module imported by `backend/app` and `scripts/` is
in `requirements.txt`. Frontend versions are locked by `package-lock.json`.

## How to re-run
```
cd backend && .venv\Scripts\python -m pip_audit
cd backend && .venv\Scripts\python -m pip check
cd frontend && npm audit
```
