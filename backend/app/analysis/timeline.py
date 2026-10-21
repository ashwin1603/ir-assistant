import json

from sqlalchemy.orm import Session

from app.models import Detection


def build_timeline(db: Session, incident_id: str) -> list[dict]:
    detections = (
        db.query(Detection)
        .filter(Detection.incident_id == incident_id)
        .order_by(Detection.first_seen.asc())
        .all()
    )
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
        }
        for d in detections
    ]
