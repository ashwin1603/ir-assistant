"""Local break-glass recovery for a locked-out admin (lost password or MFA device).

Run on the server machine itself; it talks to the database directly, not the API, and
reads backend/.env itself (via app.config) for the database path and admin username.

    python scripts/admin_recovery.py                 # the ADMIN_USERNAME from backend/.env
    python scripts/admin_recovery.py --username bob  # another admin account

Sets a new random password, clears MFA and re-enables the account. The new password
is printed ONCE to this terminal and never written to a log or the audit trail.
"""

import argparse
import os
import secrets
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
# The app's settings use a relative DB path and .env, so run from backend/ like the API does.
os.chdir(BACKEND_DIR)
sys.path.insert(0, str(BACKEND_DIR))

from app.audit import log_action  # noqa: E402
from app.auth.routes import clear_mfa  # noqa: E402
from app.auth.security import hash_password  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import User  # noqa: E402


class RecoveryError(Exception):
    pass


def recover_admin(db, username: str) -> str:
    """Reset an existing admin's password and MFA; return the new password."""
    user = db.query(User).filter(User.username == username).first()
    if user is None or user.role != "admin":
        raise RecoveryError(f"No admin account named '{username}'")
    password = secrets.token_urlsafe(18)  # 24 characters
    user.password_hash = hash_password(password)
    user.is_active = True
    user.step_up_at = None
    clear_mfa(user)
    # Audited without the password.
    log_action(db, actor="local-recovery-script", action="admin_recovery", detail=f"user={username} password+mfa reset")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", default=None, help="admin to recover (default: ADMIN_USERNAME from backend/.env)")
    args = parser.parse_args()

    username = args.username or settings.admin_username
    if not username:
        print("No --username given and ADMIN_USERNAME is not set in backend/.env.")
        return 1

    db = SessionLocal()
    try:
        password = recover_admin(db, username)
    except RecoveryError as e:
        print(e)
        return 1
    finally:
        db.close()

    print(f"Admin '{username}' recovered: MFA cleared, account enabled.")
    print(f"New password (shown once, store it now): {password}")
    print("If 'Require MFA for admin' is on, you will be asked to set up MFA at next login.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
