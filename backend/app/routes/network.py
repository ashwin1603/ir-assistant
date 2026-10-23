"""Network overview: top destinations, top processes and bytes out per
destination, plus the network rules' detections. Read-only, all roles."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.permissions import current_user
from app.collector.network import NETWORK_CHANNEL
from app.db import get_db
from app.detection.engine import run_detection
from app.detection.network_rules import NETWORK_RULES
from app.models import Detection, Event
from app.routes.detections import _to_out
from app.schemas import NetworkSummaryOut

router = APIRouter(prefix="/api/network", tags=["network"])

TOP_N = 10


@router.get("/summary", response_model=NetworkSummaryOut)
def network_summary(
    db: Session = Depends(get_db),
    _user=Depends(current_user),
    host: str | None = Query(default=None, max_length=255),
):
    run_detection(db)
    connections = db.query(Event).filter(Event.channel == NETWORK_CHANNEL, Event.provider == "network_connection")
    if host:
        connections = connections.filter(Event.host == host)
    count = func.count(Event.id).label("count")
    total_bytes = func.sum(Event.bytes_out).label("bytes_out")

    top_destinations = (
        connections.filter(Event.dst_ip.isnot(None))
        .with_entities(Event.dst_ip, count)
        .group_by(Event.dst_ip)
        .order_by(count.desc())
        .limit(TOP_N)
        .all()
    )
    top_processes = (
        connections.filter(Event.process.isnot(None))
        .with_entities(Event.process, count)
        .group_by(Event.process)
        .order_by(count.desc())
        .limit(TOP_N)
        .all()
    )
    bytes_by_destination = (
        connections.filter(Event.dst_ip.isnot(None), Event.bytes_out.isnot(None))
        .with_entities(Event.dst_ip, total_bytes)
        .group_by(Event.dst_ip)
        .order_by(total_bytes.desc())
        .limit(TOP_N)
        .all()
    )

    rule_names = [n.rule.name for n in NETWORK_RULES]
    detections = db.query(Detection).filter(Detection.rule_name.in_(rule_names))
    if host:
        detections = detections.filter(Detection.host == host)

    hosts = db.query(Event.host).filter(Event.channel == NETWORK_CHANNEL).distinct().order_by(Event.host).all()
    return NetworkSummaryOut(
        hosts=[h for (h,) in hosts],
        top_destinations=[{"dst_ip": ip, "count": c} for ip, c in top_destinations],
        top_processes=[{"process": p, "count": c} for p, c in top_processes],
        bytes_by_destination=[{"dst_ip": ip, "bytes_out": b} for ip, b in bytes_by_destination],
        detections=[_to_out(d) for d in detections.order_by(Detection.first_seen.desc()).all()],
    )
