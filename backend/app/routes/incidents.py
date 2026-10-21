import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.ai.triage import analyze_incident, check_rate_limit
from app.analysis.case_state import case_key, get_notes, get_status, status_map
from app.analysis.timeline import build_timeline
from app.audit import log_action
from app.auth.deps import get_current_user, require_role
from app.db import get_db
from app.detection.engine import run_detection
from app.models import Detection, Incident, IncidentCase, IncidentNote
from app.schemas import AnalysisOut, IncidentDetail, IncidentOut, IncidentStatusUpdate, NoteCreate, NoteOut

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _to_out(incident: Incident, status: str) -> IncidentOut:
    return IncidentOut(
        id=incident.id,
        host=incident.host,
        started_at=incident.started_at,
        ended_at=incident.ended_at,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level,
        detection_count=incident.detection_count,
        status=status,
    )


def _get_or_404(db: Session, incident_id: str) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    status: str | None = Query(default=None, pattern="^(new|investigating|contained|closed)$"),
):
    run_detection(db)
    statuses = status_map(db)
    incidents = [
        _to_out(incident, statuses.get(case_key(incident), "new"))
        for incident in db.query(Incident).order_by(Incident.started_at.desc()).all()
    ]
    if status:
        incidents = [incident for incident in incidents if incident.status == status]
    return incidents


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    run_detection(db)
    incident = _get_or_404(db, incident_id)
    return IncidentDetail(
        **_to_out(incident, get_status(db, incident)).model_dump(),
        timeline=build_timeline(db, incident.id),
        notes=get_notes(db, incident),
    )


@router.put("/{incident_id}/status", response_model=IncidentOut)
def set_status(
    incident_id: str,
    body: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    incident = _get_or_404(db, incident_id)
    key = case_key(incident)
    case = db.get(IncidentCase, key) or IncidentCase(case_key=key)
    old_status = case.status or "new"
    case.status = body.status
    case.updated_by = user.username
    case.updated_at = datetime.now(timezone.utc)
    db.add(case)
    db.commit()
    log_action(db, actor=user.username, action="incident_status", detail=f"case={key} {old_status} -> {body.status}")
    return _to_out(incident, body.status)


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(
    incident_id: str,
    body: NoteCreate,
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    incident = _get_or_404(db, incident_id)
    note = IncidentNote(case_key=case_key(incident), author=user.username, text=body.text)
    db.add(note)
    db.commit()
    # Note text can be sensitive; the audit log records that a note was added, not its content.
    log_action(db, actor=user.username, action="incident_note", detail=f"case={note.case_key} note_id={note.id}")
    return note


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
