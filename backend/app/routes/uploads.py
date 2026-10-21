import logging
import uuid
from pathlib import Path, PurePath

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.deps import require_role
from app.collector.upload_parser import (
    ALLOWED_EXTENSIONS,
    UploadParseError,
    content_matches_extension,
    parse_upload,
)
from app.config import settings
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Event
from app.rate_limit import limiter
from app.schemas import EventIn

logger = logging.getLogger("ir_assistant")

router = APIRouter(prefix="/api/uploads", tags=["uploads"])

CHUNK_SIZE = 1024 * 1024


def _upload_dir() -> Path:
    # Lives next to the backend, never inside the frontend's served folder.
    path = Path(settings.upload_dir).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _reject(db: Session, user, code: int, message: str, original_name: str):
    log_action(db, actor=user.username, action="upload", detail=f"rejected '{original_name}': {message}", success=False)
    raise HTTPException(status_code=code, detail=message)


def _is_duplicate(db: Session, event: EventIn, seen: set) -> bool:
    # Same key as /events/ingest: (record_id, host, channel). Events without a
    # record id (e.g. some CSVs) fall back to (event_id, timestamp, host, channel).
    if event.record_id is not None:
        key = ("rec", event.record_id, event.host, event.channel)
        query = db.query(Event.id).filter(
            Event.record_id == event.record_id, Event.host == event.host, Event.channel == event.channel
        )
    else:
        key = ("ts", event.event_id, event.timestamp, event.host, event.channel)
        query = db.query(Event.id).filter(
            Event.event_id == event.event_id,
            Event.timestamp == event.timestamp,
            Event.host == event.host,
            Event.channel == event.channel,
        )
    if key in seen or query.first():
        return True
    seen.add(key)
    return False


@router.post("", status_code=201)
@limiter.limit("10/minute")
def upload_log_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    # Only the basename's extension is used; the client-supplied name never
    # becomes part of a filesystem path, so "../../x.json" cannot escape.
    original_name = PurePath((file.filename or "").replace("\\", "/")).name[:255]
    ext = PurePath(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        _reject(db, user, 400, "Unsupported file type. Allowed: .evtx, .json, .csv", original_name)

    # Read in chunks and stop as soon as the limit is passed.
    max_bytes = settings.upload_max_mb * 1024 * 1024
    data = bytearray()
    # Sync route on purpose: FastAPI runs it in a worker thread, so slow .evtx
    # parsing does not block other requests.
    while chunk := file.file.read(CHUNK_SIZE):
        data.extend(chunk)
        if len(data) > max_bytes:
            _reject(db, user, 413, f"File too large (max {settings.upload_max_mb} MB)", original_name)
    if not data:
        _reject(db, user, 400, "File is empty", original_name)
    if not content_matches_extension(ext, bytes(data[:4096])):
        _reject(db, user, 400, f"File content does not match the {ext} extension", original_name)

    stored_path = _upload_dir() / f"{uuid.uuid4().hex}{ext}"
    stored_path.write_bytes(data)

    try:
        parsed = parse_upload(ext, bytes(data), str(stored_path))
        events = [EventIn(**item) for item in parsed]
    except UploadParseError as exc:
        stored_path.unlink(missing_ok=True)
        _reject(db, user, 400, str(exc), original_name)
    except ValidationError as exc:
        logger.warning("upload validation failed for %s: %s", stored_path.name, exc.errors()[:3])
        stored_path.unlink(missing_ok=True)
        _reject(db, user, 400, "File contains events with invalid or oversized fields", original_name)

    inserted = skipped = 0
    seen: set = set()
    for event in events:
        if _is_duplicate(db, event, seen):
            skipped += 1
            continue
        db.add(Event(**event.model_dump()))
        inserted += 1
    db.commit()

    run_detection(db)
    log_action(
        db,
        actor=user.username,
        action="upload",
        detail=f"'{original_name}' -> {stored_path.name}: {inserted} inserted, {skipped} duplicates",
        success=True,
    )
    return {"filename": original_name, "parsed": len(events), "inserted": inserted, "duplicates": skipped}
