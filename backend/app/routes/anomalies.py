import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.analysis.iforest import ANOMALY_THRESHOLD, IsolationForest, extract_features, top_features
from app.auth.deps import get_current_user
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Detection, Event
from app.schemas import AnomalyOut, AnomalyReport

router = APIRouter(prefix="/api/anomalies", tags=["anomalies"])

MIN_TRAINING_EVENTS = 10


def score_anomalies(db: Session, limit: int) -> AnomalyReport:
    """Train on real 4688 events, score every 4688 event, return the top `limit`.
    Kept apart from detections/incidents on purpose: these are unmapped hints."""
    events = db.query(Event).filter(Event.event_id == 4688).order_by(Event.timestamp, Event.id).all()
    training = [e for e in events if e.source != "simulated"]
    if len(training) < MIN_TRAINING_EVENTS:
        return AnomalyReport(trained_on=len(training), scored=0, threshold=ANOMALY_THRESHOLD,
                             anomaly_rate_real=0.0, items=[])

    X_train = extract_features(training, training)
    X_all = extract_features(events, training)
    model = IsolationForest().fit(X_train)
    scores = model.score(X_all)

    rule_hits: set[str] = set()
    for (ids,) in db.query(Detection.matched_event_ids).all():
        rule_hits.update(json.loads(ids))

    is_real = [e.source != "simulated" for e in events]
    real_scores = scores[is_real]
    anomaly_rate = float((real_scores >= ANOMALY_THRESHOLD).mean())

    order = sorted(range(len(events)), key=lambda i: (-scores[i], events[i].id))
    items = []
    for rank, i in enumerate(order[:limit], start=1):
        e = events[i]
        items.append(AnomalyOut(
            event_id=e.id, timestamp=e.timestamp, host=e.host, source=e.source,
            process=e.process, parent_process=e.parent_process, command_line=e.command_line,
            score=round(float(scores[i]), 4), rank=rank,
            is_anomaly=bool(scores[i] >= ANOMALY_THRESHOLD),
            top_features=top_features(X_all[i], X_train),
            also_matched_rule=e.id in rule_hits,
        ))
    return AnomalyReport(trained_on=len(training), scored=len(events), threshold=ANOMALY_THRESHOLD,
                         anomaly_rate_real=round(anomaly_rate, 4), items=items)


@router.get("", response_model=AnomalyReport)
def list_anomalies(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=500),
):
    run_detection(db)
    return score_anomalies(db, limit)
