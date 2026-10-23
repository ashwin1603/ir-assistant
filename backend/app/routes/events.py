from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.permissions import current_user
from app.auth.redaction import TextRedactor, redact_command, sees_command_lines
from app.db import get_db
from app.detection.threat_intel import load_index, match_event
from app.models import Event
from app.schemas import EventIngestRequest, EventOut, EventPage

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest", status_code=201)
def ingest_events(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
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
    host: str | None = Query(default=None, max_length=255),
):
    # Only ever removes synthetic demo events (scripts/seed_simulated_events.py);
    # real collected events cannot be deleted through the API.
    query = db.query(Event).filter(Event.source == "simulated")
    if host:
        query = query.filter(Event.host == host)
    deleted = query.delete()
    db.commit()
    log_action(db, actor="collector", action="wipe_simulated", detail=f"{deleted} deleted", success=True)
    return {"deleted": deleted}


@router.get("", response_model=EventPage)
def list_events(
    db: Session = Depends(get_db),
    user=Depends(current_user),
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
    index = load_index(db)
    out = [EventOut.model_validate({**EventOut.model_validate(e).model_dump(), "ti_matches": match_event(e, index)}) for e in items]
    if not sees_command_lines(user):
        # Viewers: the 4688 message repeats the command line, so it is redacted too.
        for e, o in zip(items, out):
            o.command_line = redact_command(e.command_line, e.process)
            o.message = TextRedactor([e]).text(o.message) if o.message else o.message
    return EventPage(total=total, items=out)
