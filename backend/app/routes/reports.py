import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.analysis.timeline import build_timeline
from app.auth.deps import get_current_user
from app.db import get_db
from app.models import Action, AIAnalysis, Incident
from app.schemas import AnalysisOut, IncidentDetail, ReportOut

router = APIRouter(prefix="/api/incidents", tags=["reports"])


@router.get("/{incident_id}/report", response_model=ReportOut)
def get_report(incident_id: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = build_timeline(db, incident.id)
    incident_detail = IncidentDetail(
        id=incident.id,
        host=incident.host,
        started_at=incident.started_at,
        ended_at=incident.ended_at,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level,
        detection_count=incident.detection_count,
        timeline=timeline,
    )

    latest_analysis = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.incident_id == incident_id)
        .order_by(AIAnalysis.created_at.desc())
        .first()
    )
    analysis_out = None
    if latest_analysis:
        analysis_out = AnalysisOut(
            incident_id=incident_id,
            provider=latest_analysis.provider,
            degraded=latest_analysis.degraded,
            verdict=latest_analysis.verdict,
            confidence=latest_analysis.confidence,
            reasoning=latest_analysis.reasoning,
            narrative=latest_analysis.narrative,
            risk_explanation=latest_analysis.risk_explanation,
            findings=json.loads(latest_analysis.findings),
            recommended_actions=json.loads(latest_analysis.recommended_actions),
            created_at=latest_analysis.created_at,
        )

    actions = db.query(Action).filter(Action.incident_id == incident_id).order_by(Action.created_at.asc()).all()

    return ReportOut(
        incident=incident_detail,
        analysis=analysis_out,
        actions=actions,
        generated_at=datetime.now(timezone.utc),
    )
