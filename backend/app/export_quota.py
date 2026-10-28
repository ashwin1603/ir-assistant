from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit import log_action
from app.config import settings
from app.models import ExportUsage


def consume_export_quota(db: Session, username: str, kind: str) -> None:
    """Allow a bounded number of user-triggered downloads in a rolling window."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(minutes=settings.export_quota_minutes)
    count = db.query(ExportUsage).filter(
        ExportUsage.actor == username, ExportUsage.created_at >= cutoff
    ).count()
    if count >= settings.export_quota_count:
        log_action(db, actor=username, action="export_quota_alert", detail=f"blocked {kind}; rolling quota exceeded", success=False)
        raise HTTPException(status_code=429, detail="Download/export quota exceeded; try again later")
    db.add(ExportUsage(actor=username, created_at=now))
    db.commit()
