import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.ai.triage import analyze_incident, check_rate_limit
from app.analysis.timeline import build_timeline
from app.auth.deps import get_current_user, require_role
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Detection, Incident
from app.schemas import AnalysisOut, IncidentDetail, IncidentOut

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    run_detection(db)
    return db.query(Incident).order_by(Incident.started_at.desc()).all()


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    run_detection(db)
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    timeline = build_timeline(db, incident.id)
    return IncidentDetail(
        id=incident.id,
        host=incident.host,
        started_at=incident.started_at,
        ended_at=incident.ended_at,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level,
        detection_count=incident.detection_count,
        timeline=timeline,
    )


@router.post("/{incident_id}/analyze", response_model=AnalysisOut)
def analyze(
    incident_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    run_detection(db)
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not check_rate_limit(db, user.username):
        raise HTTPException(status_code=429, detail="AI analysis rate limit exceeded, try again later")

    detections = db.query(Detection).filter(Detection.incident_id == incident_id).all()
    analysis = analyze_incident(db, incident_id, detections, actor=user.username)

    return AnalysisOut(
        incident_id=incident_id,
        provider=analysis.provider,
        degraded=analysis.degraded,
        verdict=analysis.verdict,
        confidence=analysis.confidence,
        reasoning=analysis.reasoning,
        narrative=analysis.narrative,
        risk_explanation=analysis.risk_explanation,
        findings=json.loads(analysis.findings),
        recommended_actions=json.loads(analysis.recommended_actions),
        created_at=analysis.created_at,
    )
