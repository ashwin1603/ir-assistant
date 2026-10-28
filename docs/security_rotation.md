# Per-machine credential rotation

Perform these steps separately on every clone before it is shared or presented. Use a private password manager or an approved secret store. Never paste values into chat, tickets, screenshots, or source control.

## Before starting

1. Close the frontend, backend, and collector.
2. Back up `backend/ir_assistant.db` securely if the demo data must be retained. Do not commit the backup.
3. Keep the existing `DATA_ENCRYPTION_KEY` unchanged. Rotating or losing it can make stored MFA secrets unreadable.
4. Open `backend/.env` in a local editor without copying its values elsewhere.

## Rotate the JWT signing secret

Generate a new random value in a trusted local password manager or secrets tool and replace only `JWT_SECRET` in `backend/.env`. Restart the backend. All existing access, MFA challenge, and MFA setup tokens signed with the old key will stop working; users must sign in again. Verify a fresh login and logout.

## Rotate the collector key

Generate a new random value and replace `COLLECTOR_API_KEY` in `backend/.env`. Restart the backend. The seed scripts read this setting at runtime. Restart any collector and confirm ingestion succeeds. Do not copy the key into scripts or command history.

## Rotate the admin password

Changing `ADMIN_PASSWORD` in `.env` only sets the password when the configured admin account is first created; it does not update an existing user. With the current admin signed in, use the user-management Settings page to reset the admin account password (the action requires step-up authentication), or run `scripts/admin_recovery.py` locally if the account is inaccessible. The recovery script prints the new password once to the terminal; store it immediately and keep the terminal private. Do not place a password in screenshots or notes.

## Finish

1. Restart the app and log in with the rotated admin password.
2. Check `/api/health`, confirm one fresh login, and confirm that an old browser session is rejected after the JWT key change.
3. Confirm the collector and both demo seed scripts still work with the new collector key.
4. Confirm `backend/.env` remains ignored by Git (`git status --short` must not list it).
