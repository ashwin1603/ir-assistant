import json

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.permissions import current_user
from app.db import get_db
from app.detection.engine import run_detection
from app.detection.threat_intel import matches_for_event_ids, unique_matches
from app.export import MAX_EXPORT_ROWS, csv_response, pick_columns
from app.export_quota import consume_export_quota
from app.models import Detection
from app.rate_limit import limiter
from app.schemas import DetectionOut

router = APIRouter(prefix="/api/detections", tags=["detections"])


def _to_out(detection: Detection, ti_by_event: dict[str, list[dict]] | None = None) -> DetectionOut:
    event_ids = json.loads(detection.matched_event_ids)
    return DetectionOut(
        id=detection.id,
        incident_id=detection.incident_id,
        rule_name=detection.rule_name,
        technique_ids=json.loads(detection.technique_ids),
        tactics=json.loads(detection.tactics),
        severity=detection.severity,
        confidence=detection.confidence,
        host=detection.host,
        event_count=detection.event_count,
        matched_event_ids=event_ids,
        first_seen=detection.first_seen,
        last_seen=detection.last_seen,
        risk_score=detection.risk_score,
        risk_level=detection.risk_level,
        ti_matches=unique_matches(ti_by_event or {}, event_ids),
        summary=detection.summary,
    )


def _filtered(db: Session, host: str | None, technique_id: str | None) -> list[Detection]:
    run_detection(db)
    query = db.query(Detection)
    if host:
        query = query.filter(Detection.host == host)
    detections = query.order_by(Detection.first_seen.desc()).all()
    if technique_id:
        detections = [d for d in detections if technique_id in json.loads(d.technique_ids)]
    return detections


@router.get("", response_model=list[DetectionOut])
def list_detections(
    db: Session = Depends(get_db),
    _user=Depends(current_user),
    host: str | None = Query(default=None, max_length=255),
    technique_id: str | None = Query(default=None, max_length=32),
):
    detections = _filtered(db, host, technique_id)
    ti_by_event = matches_for_event_ids(db, {i for d in detections for i in json.loads(d.matched_event_ids)})
    return [_to_out(d, ti_by_event) for d in detections]


EXPORT_COLUMNS = ["id", "rule_name", "technique_ids", "tactics", "host", "event_count", "severity", "confidence",
                  "risk_score", "risk_level", "first_seen", "last_seen", "incident_id", "summary"]


@router.get("/export")
@limiter.limit("10/minute")
def export_detections(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(current_user),
    host: str | None = Query(default=None, max_length=255),
    technique_id: str | None = Query(default=None, max_length=32),
    columns: str | None = Query(default=None, max_length=500),
):
    """CSV of the current Detections view: the same fields every role already sees in the list."""
    consume_export_quota(db, user.username, "detections CSV")
    picked = pick_columns(columns, EXPORT_COLUMNS)
    detections = _filtered(db, host, technique_id)
    truncated = len(detections) > MAX_EXPORT_ROWS
    rows = []
    for d in detections[:MAX_EXPORT_ROWS]:
        o = _to_out(d)
        rows.append({**o.model_dump(), "technique_ids": " ".join(o.technique_ids), "tactics": "; ".join(o.tactics),
                     "first_seen": o.first_seen.isoformat(), "last_seen": o.last_seen.isoformat()})
    log_action(db, actor=user.username, action="export", detail=f"detections: {len(rows)} rows{' (capped)' if truncated else ''}")
    return csv_response(rows, picked, "detections.csv", truncated)
