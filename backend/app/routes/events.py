from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.deps import get_current_user, require_collector_key
from app.db import get_db
from app.models import Event
from app.schemas import EventIngestRequest, EventPage

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest", status_code=201)
def ingest_events(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
    _collector=Depends(require_collector_key),
):
    inserted = 0
    skipped = 0
    for item in payload.events:
        if item.record_id is not None:
            duplicate = (
                db.query(Event.id)
                .filter(
                    Event.record_id == item.record_id,
                    Event.host == item.host,
                    Event.channel == item.channel,
                )
                .first()
            )
            if duplicate:
                skipped += 1
                continue
        db.add(Event(**item.model_dump()))
        inserted += 1
    db.commit()
    log_action(db, actor="collector", action="ingest", detail=f"{inserted} inserted, {skipped} skipped", success=True)
    return {"ingested": inserted, "skipped": skipped}


@router.delete("/simulated")
def wipe_simulated_events(
    db: Session = Depends(get_db),
    _collector=Depends(require_collector_key),
):
    # Only ever removes synthetic demo events (scripts/seed_simulated_events.py);
    # real collected events cannot be deleted through the API.
    deleted = db.query(Event).filter(Event.source == "simulated").delete()
    db.commit()
    log_action(db, actor="collector", action="wipe_simulated", detail=f"{deleted} deleted", success=True)
    return {"deleted": deleted}


@router.get("", response_model=EventPage)
def list_events(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    q: str | None = Query(default=None, max_length=200),
    channel: str | None = Query(default=None, max_length=255),
    event_id: int | None = Query(default=None),
    host: str | None = Query(default=None, max_length=255),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    query = db.query(Event)
    if channel:
        query = query.filter(Event.channel == channel)
    if event_id is not None:
        query = query.filter(Event.event_id == event_id)
    if host:
        query = query.filter(Event.host == host)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Event.message.like(like),
                Event.command_line.like(like),
                Event.user.like(like),
                Event.process.like(like),
            )
        )

    total = query.count()
    items = query.order_by(Event.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return EventPage(total=total, items=items)
