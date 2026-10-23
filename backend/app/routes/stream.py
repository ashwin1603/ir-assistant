"""GET /api/stream: small "something changed" signals for live UI updates.

- Auth is the normal Authorization: Bearer header (the browser reads the stream with
  fetch, never EventSource, so the token is never put in a query string or URL).
- Payload = counts and the newest event/detection ids only. No messages, command lines,
  hosts or users, so there is nothing to redact for viewers.
- Every poll opens a short DB session, runs a few COUNT queries and closes it. It never
  runs detection (pages do that when they reload). The request's own DB session is closed
  before streaming starts.
- No long-held connections: each stream ends after settings.stream_max_seconds and the
  client reconnects. At most MAX_STREAMS_PER_USER open streams per user (429 beyond).
- A heartbeat comment line is sent when nothing changed, so proxies keep the stream open
  and the client can tell the server is alive.
"""

import asyncio
import json
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.permissions import current_user
from app.config import settings
from app.db import get_db
from app.models import Action, Detection, Event, Incident

router = APIRouter(prefix="/api/stream", tags=["stream"])

MAX_STREAMS_PER_USER = 2
HEARTBEAT_SECONDS = 15

# username -> expiry times of that user's open streams. A slot also expires on its own
# shortly after the stream's deadline, so a stream cancelled before it ever started
# cannot block the user forever.
_open_streams: dict[str, list[float]] = {}
_lock = threading.Lock()


def _live(username: str) -> list[float]:
    now = time.monotonic()
    slots = [t for t in _open_streams.get(username, []) if t > now]
    _open_streams[username] = slots
    return slots


def acquire_slot(username: str) -> float | None:
    """Returns the slot (its expiry time) or None when the user already has the maximum open."""
    with _lock:
        slots = _live(username)
        if len(slots) >= MAX_STREAMS_PER_USER:
            return None
        slot = time.monotonic() + settings.stream_max_seconds + 10
        slots.append(slot)
        return slot


def release_slot(username: str, slot: float) -> None:
    with _lock:
        slots = _open_streams.get(username, [])
        if slot in slots:
            slots.remove(slot)
        if not slots:
            _open_streams.pop(username, None)


def open_streams(username: str) -> int:
    with _lock:
        return len(_live(username))


def snapshot(db: Session) -> dict:
    """Lightweight counters only (indexed COUNTs and two newest ids)."""
    newest_event = db.query(Event.id).order_by(Event.timestamp.desc(), Event.id.desc()).limit(1).scalar()
    newest_detection = db.query(Detection.id).order_by(Detection.first_seen.desc(), Detection.id.desc()).limit(1).scalar()
    return {
        "events": db.query(func.count(Event.id)).scalar(),
        "detections": db.query(func.count(Detection.id)).scalar(),
        "incidents": db.query(func.count(Incident.id)).scalar(),
        "pending_actions": db.query(func.count(Action.id)).filter(Action.status == "pending").scalar(),
        "latest_event_id": newest_event,
        "latest_detection_id": newest_detection,
    }


def _short_session_snapshot(session_factory) -> dict:
    # session_factory is get_db (or the test override): a generator yielding one session.
    sessions = session_factory()
    db = next(sessions)
    try:
        return snapshot(db)
    finally:
        sessions.close()


@router.get("")
async def stream(request: Request, user=Depends(current_user), db: Session = Depends(get_db)):
    username = user.username
    db.close()  # the auth lookup is done; don't keep this connection for the whole stream
    slot = acquire_slot(username)
    if slot is None:
        raise HTTPException(status_code=429, detail="Too many live streams open")
    session_factory = request.app.dependency_overrides.get(get_db, get_db)

    async def events():
        try:
            last = None
            last_sent = time.monotonic()
            deadline = time.monotonic() + settings.stream_max_seconds
            yield "retry: 3000\n\n"
            while time.monotonic() < deadline:
                if await request.is_disconnected():
                    break
                current = await asyncio.to_thread(_short_session_snapshot, session_factory)
                if current != last:
                    last = current
                    last_sent = time.monotonic()
                    yield f"data: {json.dumps(current)}\n\n"
                elif time.monotonic() - last_sent >= HEARTBEAT_SECONDS:
                    last_sent = time.monotonic()
                    yield ": heartbeat\n\n"
                await asyncio.sleep(settings.stream_poll_seconds)
        finally:
            release_slot(username, slot)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
