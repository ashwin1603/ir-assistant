"""Analyst-owned incident state (status + notes) that survives regrouping.

Incident ids are content hashes of their detection ids, so they change when a
new detection joins an incident. Status and notes are stored against
case_key = "host|started_at" instead. Caveat: if an earlier detection joins
and moves the start time, the incident starts again as "new".
"""

from datetime import timezone

from sqlalchemy.orm import Session

from app.models import Incident, IncidentCase, IncidentNote


def case_key(incident: Incident) -> str:
    started = incident.started_at
    # SQLite returns naive datetimes (UTC); normalise so both forms give one key.
    if started.tzinfo is not None:
        started = started.astimezone(timezone.utc).replace(tzinfo=None)
    return f"{incident.host}|{started.isoformat()}"


def status_map(db: Session) -> dict[str, str]:
    return {case.case_key: case.status for case in db.query(IncidentCase).all()}


def get_status(db: Session, incident: Incident) -> str:
    case = db.get(IncidentCase, case_key(incident))
    return case.status if case else "new"


def get_notes(db: Session, incident: Incident) -> list[IncidentNote]:
    return (
        db.query(IncidentNote)
        .filter(IncidentNote.case_key == case_key(incident))
        .order_by(IncidentNote.created_at.asc())
        .all()
    )
