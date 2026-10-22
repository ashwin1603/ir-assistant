import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.analysis.artifacts import extract_iocs
from app.analysis.case_state import get_notes, get_status
from app.analysis.report import attack_table, impact_text, top_actions, what_happened
from app.analysis.timeline import build_timeline
from app.auth.deps import get_current_user
from app.db import get_db
from app.models import Action, AIAnalysis, Incident
from app.schemas import AnalysisOut, ExecutiveSummary, IncidentDetail, ReportOut

router = APIRouter(prefix="/api/incidents", tags=["reports"])


@router.get("/{incident_id}/report", response_model=ReportOut)
def get_report(incident_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
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
        status=get_status(db, incident),
        timeline=timeline,
        notes=get_notes(db, incident),
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

    executive = ExecutiveSummary(
        what_happened=what_happened(timeline),
        impact=impact_text(incident.risk_level),
        top_actions=top_actions(actions),
    )

    return ReportOut(
        incident=incident_detail,
        analysis=analysis_out,
        actions=actions,
        attack=attack_table(timeline),
        iocs=extract_iocs(db, incident.id),
        executive=executive,
        generated_at=datetime.now(timezone.utc),
        generated_by=user.username,
    )
