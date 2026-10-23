"""Step-up authentication for the most sensitive admin actions.

The admin re-enters their password (or an MFA code if MFA is enabled) at
POST /api/auth/step-up. That stamps users.step_up_at; for STEP_UP_MINUTES
afterwards, routes that depend on `require_step_up` are allowed."""

from datetime import datetime, timedelta, timezone

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.auth.permissions import current_user, deny
from app.db import get_db
from app.models import User

STEP_UP_MINUTES = 5
STEP_UP_REQUIRED = "Step-up authentication required"


def has_recent_step_up(user: User, now: datetime | None = None) -> bool:
    if user.step_up_at is None:
        return False
    now = now or datetime.now(timezone.utc)
    stamped = user.step_up_at if user.step_up_at.tzinfo else user.step_up_at.replace(tzinfo=timezone.utc)
    return now - stamped < timedelta(minutes=STEP_UP_MINUTES)


def require_step_up(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)) -> User:
    if not has_recent_step_up(user):
        raise deny(db, user, request, "step-up required", detail=STEP_UP_REQUIRED)
    return user
