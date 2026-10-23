"""Admin-editable runtime settings stored in the app_settings table. Each
getter falls back to the .env/config.py default when no row exists."""

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSetting

AI_CALLS_PER_HOUR = "ai_calls_per_hour"
REQUIRE_ADMIN_MFA = "require_admin_mfa"


def get_ai_calls_per_hour(db: Session) -> int:
    row = db.get(AppSetting, AI_CALLS_PER_HOUR)
    return int(row.value) if row else settings.ai_calls_per_hour


def set_ai_calls_per_hour(db: Session, value: int) -> None:
    _set(db, AI_CALLS_PER_HOUR, str(value))


def get_require_admin_mfa(db: Session) -> bool:
    """Default OFF. When ON, an admin without MFA is sent through MFA setup at login."""
    row = db.get(AppSetting, REQUIRE_ADMIN_MFA)
    return row is not None and row.value == "true"


def set_require_admin_mfa(db: Session, value: bool) -> None:
    _set(db, REQUIRE_ADMIN_MFA, "true" if value else "false")


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()
