from sqlalchemy.orm import Session

from app.models import AuditLog


def log_action(db: Session, actor: str | None, action: str, detail: str | None = None, success: bool = True) -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail, success=success))
    db.commit()
