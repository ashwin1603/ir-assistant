from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.deps import get_current_user, require_role
from app.db import get_db
from app.models import Action
from app.schemas import ActionOut

router = APIRouter(prefix="/api/actions", tags=["actions"])


@router.get("", response_model=list[ActionOut])
def list_actions(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    incident_id: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, pattern="^(pending|approved|rejected)$"),
):
    query = db.query(Action)
    if incident_id:
        query = query.filter(Action.incident_id == incident_id)
    if status:
        query = query.filter(Action.status == status)
    return query.order_by(Action.created_at.desc()).all()


def _decide(action_id: str, new_status: str, db: Session, user) -> Action:
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "pending":
        raise HTTPException(status_code=409, detail=f"Action already {action.status}")

    action.status = new_status
    action.decided_by = user.username
    action.decided_at = datetime.now(timezone.utc)
    db.commit()

    log_action(
        db,
        actor=user.username,
        action=f"action_{new_status}",
        detail=f"incident={action.incident_id} action_id={action.id} (simulated, not executed): {action.action_text}",
        success=True,
    )
    return action


@router.post("/{action_id}/approve", response_model=ActionOut)
def approve_action(action_id: str, db: Session = Depends(get_db), user=Depends(require_role("admin", "analyst"))):
    return _decide(action_id, "approved", db, user)


@router.post("/{action_id}/reject", response_model=ActionOut)
def reject_action(action_id: str, db: Session = Depends(get_db), user=Depends(require_role("admin", "analyst"))):
    return _decide(action_id, "rejected", db, user)
