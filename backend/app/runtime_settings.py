"""Admin-editable runtime settings stored in the app_settings table. Each
getter falls back to the .env/config.py default when no row exists."""

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSetting

AI_CALLS_PER_HOUR = "ai_calls_per_hour"


def get_ai_calls_per_hour(db: Session) -> int:
    row = db.get(AppSetting, AI_CALLS_PER_HOUR)
    return int(row.value) if row else settings.ai_calls_per_hour


def set_ai_calls_per_hour(db: Session, value: int) -> None:
    row = db.get(AppSetting, AI_CALLS_PER_HOUR)
    if row:
        row.value = str(value)
    else:
        db.add(AppSetting(key=AI_CALLS_PER_HOUR, value=str(value)))
    db.commit()
