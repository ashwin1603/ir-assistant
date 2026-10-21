import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Detection
from app.schemas import DetectionOut

router = APIRouter(prefix="/api/detections", tags=["detections"])


def _to_out(detection: Detection) -> DetectionOut:
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
        matched_event_ids=json.loads(detection.matched_event_ids),
        first_seen=detection.first_seen,
        last_seen=detection.last_seen,
        risk_score=detection.risk_score,
        risk_level=detection.risk_level,
    )


@router.get("", response_model=list[DetectionOut])
def list_detections(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    host: str | None = Query(default=None, max_length=255),
    technique_id: str | None = Query(default=None, max_length=32),
):
    run_detection(db)
    query = db.query(Detection)
    if host:
        query = query.filter(Detection.host == host)
    detections = query.order_by(Detection.first_seen.desc()).all()
    if technique_id:
        detections = [d for d in detections if technique_id in json.loads(d.technique_ids)]
    return [_to_out(d) for d in detections]
