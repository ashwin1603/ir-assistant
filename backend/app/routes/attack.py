"""ATT&CK coverage matrix and technique detail. Read-only, all roles."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.db import get_db
from app.detection.attack_map import DESCRIPTIONS, MITIGATIONS, TACTIC_ORDER, TACTICS, TECHNIQUE_NAMES
from app.detection.engine import effective_network_rules, effective_rules, run_detection
from app.detection.threat_intel import TI_RULE
from app.models import Detection
from app.routes.detections import _to_out
from app.schemas import AttackMatrixOut, TechniqueCell, TechniqueDetailOut, TechniqueRule

router = APIRouter(prefix="/api/attack", tags=["attack"])

RECENT_DETECTIONS_LIMIT = 20


def _covered_techniques(db: Session) -> dict[str, list]:
    """technique id -> enabled rules that detect it."""
    covered: dict[str, list] = {}
    network = [network_rule.rule for network_rule, _params in effective_network_rules(db)]
    for rule in [*effective_rules(db), TI_RULE, *network]:
        for technique_id in rule.technique_ids:
            covered.setdefault(technique_id, []).append(rule)
    return covered


def _detections_by_technique(db: Session, host: str | None) -> dict[str, list[Detection]]:
    query = db.query(Detection)
    if host:
        query = query.filter(Detection.host == host)
    grouped: dict[str, list[Detection]] = {}
    for detection in query.order_by(Detection.last_seen.desc()).all():
        for technique_id in json.loads(detection.technique_ids):
            grouped.setdefault(technique_id, []).append(detection)
    return grouped


def _cell(technique_id: str, detections: list[Detection]) -> TechniqueCell:
    top = max(detections, key=lambda d: d.risk_score, default=None)
    return TechniqueCell(
        technique_id=technique_id,
        name=TECHNIQUE_NAMES.get(technique_id, technique_id),
        hit_count=len(detections),
        max_risk_score=top.risk_score if top else None,
        max_risk_level=top.risk_level if top else None,
    )


@router.get("/matrix", response_model=AttackMatrixOut)
def attack_matrix(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    host: str | None = Query(default=None, max_length=255),
):
    run_detection(db)
    covered = _covered_techniques(db)
    hits = _detections_by_technique(db, host)

    columns: dict[str, list[TechniqueCell]] = {tactic: [] for tactic in TACTIC_ORDER}
    for technique_id in sorted(covered):
        tactic = TACTICS.get(technique_id, "Unknown")
        columns.setdefault(tactic, []).append(_cell(technique_id, hits.get(technique_id, [])))

    hosts = sorted({h for (h,) in db.query(Detection.host).distinct()})
    return AttackMatrixOut(
        tactics=[{"tactic": tactic, "techniques": cells} for tactic, cells in columns.items() if cells],
        hosts=hosts,
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueDetailOut)
def technique_detail(
    technique_id: str,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    host: str | None = Query(default=None, max_length=255),
):
    run_detection(db)
    technique_id = technique_id.upper()
    rules = _covered_techniques(db).get(technique_id)
    if not rules:
        raise HTTPException(status_code=404, detail="Technique not found")

    detections = _detections_by_technique(db, host).get(technique_id, [])
    cell = _cell(technique_id, detections)
    return TechniqueDetailOut(
        **cell.model_dump(),
        tactic=TACTICS.get(technique_id, "Unknown"),
        description=DESCRIPTIONS.get(technique_id, ""),
        rules=[
            TechniqueRule(id=r.id, name=r.name, severity=r.severity, confidence=r.confidence, kind=r.kind)
            for r in rules
        ],
        recent_detections=[_to_out(d) for d in detections[:RECENT_DETECTIONS_LIMIT]],
        mitigations=MITIGATIONS.get(technique_id, []),
    )
