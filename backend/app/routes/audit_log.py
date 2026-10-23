from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.permissions import current_user
from app.db import get_db
from app.models import AuditLog
from app.schemas import AuditLogPage

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=AuditLogPage)
def list_audit_log(
    db: Session = Depends(get_db),
    _admin=Depends(current_user),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return AuditLogPage(total=total, items=items)
