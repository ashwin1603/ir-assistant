from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.db import get_db
from app.models import AuditLog
from app.schemas import AuditLogOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_log(db: Session = Depends(get_db), _admin=Depends(require_role("admin"))):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all()
