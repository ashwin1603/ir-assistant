from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.permissions import current_user
from app.auth.redaction import TextRedactor, redact_command, sees_command_lines
from app.db import get_db, retry_on_lock
from app.detection.threat_intel import load_index, match_event
from app.export import MAX_EXPORT_ROWS, csv_response, pick_columns
from app.models import Event
from app.rate_limit import limiter
from app.schemas import EventIngestRequest, EventOut, EventPage

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest", status_code=201)
def ingest_events(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
):
    def store() -> tuple[int, int]:
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
        return inserted, skipped

    # A detection recompute may hold the write lock; retry briefly instead of failing the batch.
    inserted, skipped = retry_on_lock(db, store)
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


def _filtered(db: Session, user, q, channel, event_id, host):
    """The Log Explorer filters, shared by the list and the CSV export."""
    query = db.query(Event)
    if channel:
        query = query.filter(Event.channel == channel)
    if event_id is not None:
        query = query.filter(Event.event_id == event_id)
    if host:
        query = query.filter(Event.host == host)
    if q:
        like = f"%{q}%"
        if sees_command_lines(user):
            fields = [Event.message.like(like), Event.command_line.like(like), Event.user.like(like), Event.process.like(like)]
        else:
            # Viewers: never match on content they cannot see (command_line, message, raw),
            # or the result count becomes an oracle for redacted text.
            fields = [Event.user.like(like), Event.process.like(like), Event.host.like(like), Event.channel.like(like)]
            if q.strip().isdigit():
                fields.append(Event.event_id == int(q.strip()))
        query = query.filter(or_(*fields))
    return query


def _redact_for(user, items: list[Event], out: list[EventOut]) -> None:
    if not sees_command_lines(user):
        # Viewers: the 4688 message repeats the command line, so it is redacted too.
        for e, o in zip(items, out):
            o.command_line = redact_command(e.command_line, e.process)
            o.message = TextRedactor([e]).text(o.message) if o.message else o.message


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
    query = _filtered(db, user, q, channel, event_id, host)
    total = query.count()
    items = query.order_by(Event.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    index = load_index(db)
    out = [EventOut.model_validate({**EventOut.model_validate(e).model_dump(), "ti_matches": match_event(e, index)}) for e in items]
    _redact_for(user, items, out)
    return EventPage(total=total, items=out)


EXPORT_COLUMNS = ["id", "timestamp", "source", "host", "channel", "provider", "event_id", "user", "process",
                  "command_line", "parent_process", "src_ip", "logon_type", "dst_ip", "dst_port", "protocol", "message"]


@router.get("/export")
@limiter.limit("10/minute")
def export_events(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(current_user),
    q: str | None = Query(default=None, max_length=200),
    channel: str | None = Query(default=None, max_length=255),
    event_id: int | None = Query(default=None),
    host: str | None = Query(default=None, max_length=255),
    columns: str | None = Query(default=None, max_length=500),
):
    """CSV of the current Log Explorer view (same filters and redaction), newest first."""
    picked = pick_columns(columns, EXPORT_COLUMNS)
    items = (_filtered(db, user, q, channel, event_id, host)
             .order_by(Event.timestamp.desc()).limit(MAX_EXPORT_ROWS + 1).all())
    truncated = len(items) > MAX_EXPORT_ROWS
    items = items[:MAX_EXPORT_ROWS]
    out = [EventOut.model_validate(e) for e in items]
    _redact_for(user, items, out)
    # Audit: who exported how many rows. Never the filters or any content.
    log_action(db, actor=user.username, action="export", detail=f"events: {len(out)} rows{' (capped)' if truncated else ''}")
    rows = [{**o.model_dump(), "timestamp": o.timestamp.isoformat()} for o in out]
    return csv_response(rows, picked, "events.csv", truncated)
