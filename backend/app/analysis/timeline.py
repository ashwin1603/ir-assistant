import json

from sqlalchemy.orm import Session

from app.detection.threat_intel import matches_for_event_ids, unique_matches
from app.models import Detection


def build_timeline(db: Session, incident_id: str) -> list[dict]:
    detections = (
        db.query(Detection)
        .filter(Detection.incident_id == incident_id)
        .order_by(Detection.first_seen.asc())
        .all()
    )
    ti_by_event = matches_for_event_ids(db, {i for d in detections for i in json.loads(d.matched_event_ids)})
    return [
        {
            "detection_id": d.id,
            "rule_name": d.rule_name,
            "technique_ids": json.loads(d.technique_ids),
            "tactics": json.loads(d.tactics),
            "severity": d.severity,
            "confidence": d.confidence,
            "risk_score": d.risk_score,
            "risk_level": d.risk_level,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
            "event_ids": json.loads(d.matched_event_ids),
            "ti_matches": unique_matches(ti_by_event, json.loads(d.matched_event_ids)),
            "summary": d.summary,
        }
        for d in detections
    ]
