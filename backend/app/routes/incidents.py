from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.analysis.timeline import build_timeline
from app.auth.deps import get_current_user
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Incident
from app.schemas import IncidentDetail, IncidentOut

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
