from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.analysis.artifacts import extract_iocs, firewall_block_script, iocs_to_csv, isolation_script
from app.audit import log_action
from app.auth.deps import get_current_user, require_role
from app.db import get_db
from app.models import Incident

router = APIRouter(prefix="/api/incidents", tags=["artifacts"])


def _get_or_404(db: Session, incident_id: str) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _attachment(body: str, media_type: str, filename: str) -> Response:
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{incident_id}/iocs")
def download_iocs(
    incident_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    incident = _get_or_404(db, incident_id)
    iocs = extract_iocs(db, incident.id)
    log_action(db, actor=user.username, action="ioc_download", detail=f"incident={incident.id} format={format} count={len(iocs)}")
    if format == "csv":
        return _attachment(iocs_to_csv(iocs), "text/csv", f"iocs-{incident.id[:8]}.csv")
    return iocs


@router.get("/{incident_id}/scripts/{kind}")
def download_script(
    incident_id: str,
    kind: str = Path(pattern="^(firewall|isolation)$"),
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    # Text only: the script is returned for human review and is never executed by the app.
    incident = _get_or_404(db, incident_id)
    if kind == "firewall":
        body = firewall_block_script(incident.host, incident.id, extract_iocs(db, incident.id))
    else:
        body = isolation_script(incident.host, incident.id)
    log_action(db, actor=user.username, action="script_download", detail=f"incident={incident.id} kind={kind}")
    return _attachment(body, "text/plain; charset=utf-8", f"{kind}-{incident.id[:8]}.ps1.txt")
