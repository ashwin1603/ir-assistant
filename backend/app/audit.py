import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import AuditChainState, AuditLog


def _digest(row: AuditLog, previous: str) -> str:
    stamp = row.timestamp
    if stamp is not None:
        stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
    fields = {
        "id": row.id, "timestamp": stamp.isoformat() if stamp else None,
        "actor": row.actor, "action": row.action, "detail": row.detail,
        "success": row.success, "previous_hash": previous,
    }
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def initialize_audit_chain(db: Session) -> None:
    rows = db.query(AuditLog).order_by(AuditLog.timestamp, AuditLog.id).all()
    legacy_rows = bool(rows) and all(not row.entry_hash for row in rows)
    if legacy_rows:
        previous = "0" * 64
        for row in rows:
            row.previous_hash = previous
            row.entry_hash = _digest(row, previous)
            previous = row.entry_hash
        db.commit()
    head = rows[-1].entry_hash if rows else "0" * 64
    state = db.get(AuditChainState, 1)
    if state is None and (not rows or legacy_rows):
        db.add(AuditChainState(id=1, head_hash=head))
        db.commit()


def verify_audit_chain(db: Session) -> tuple[bool, str | None]:
    rows = db.query(AuditLog).all()
    by_previous: dict[str, list[AuditLog]] = {}
    for row in rows:
        by_previous.setdefault(row.previous_hash, []).append(row)
    previous = "0" * 64
    visited = 0
    while previous in by_previous:
        candidates = by_previous[previous]
        if len(candidates) != 1:
            return False, candidates[0].id
        row = candidates[0]
        if row.entry_hash != _digest(row, previous):
            return False, row.id
        previous = row.entry_hash
        visited += 1
    if visited != len(rows):
        broken = next((r for r in rows if r.previous_hash == previous), rows[0] if rows else None)
        return False, broken.id if broken else None
    state = db.get(AuditChainState, 1)
    expected_head = state.head_hash if state else "0" * 64
    if previous != expected_head:
        return False, rows[-1].id if rows else None
    return True, None


def migrate_audit_chain(db: Session) -> None:
    """Backfill the hash chain once for databases created before this feature."""
    initialize_audit_chain(db)


def log_action(db: Session, actor: str | None, action: str, detail: str | None = None, success: bool = True) -> None:
    rows = db.query(AuditLog).all()
    referenced = {row.previous_hash for row in rows if row.previous_hash}
    tails = [row for row in rows if row.entry_hash and row.entry_hash not in referenced]
    if len(tails) > 1 or (rows and not tails):
        raise RuntimeError("Audit chain integrity failure; refusing to append")
    previous = tails[0].entry_hash if tails else "0" * 64
    if rows and not verify_audit_chain(db)[0]:
        raise RuntimeError("Audit chain integrity failure; refusing to append")
    state = db.get(AuditChainState, 1)
    if state and state.head_hash != previous:
        raise RuntimeError("Audit chain integrity failure; refusing to append")
    row = AuditLog(actor=actor, action=action, detail=detail, success=success, previous_hash=previous)
    db.add(row)
    db.flush()
    row.entry_hash = _digest(row, previous)
    if state is None:
        state = AuditChainState(id=1, head_hash=row.entry_hash)
        db.add(state)
    else:
        state.head_hash = row.entry_hash
    db.commit()
