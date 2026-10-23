from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_collector_key
from app.db import get_db
from app.models import Device, Event
from app.schemas import DeviceOut, HeartbeatIn

router = APIRouter(prefix="/api/devices", tags=["devices"])

ONLINE_SECONDS = 60
STALE_SECONDS = 300


def _utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes that are really UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def device_status(last_seen: datetime | None, now: datetime) -> str:
    """online < 60s since last heartbeat, stale < 5 min, otherwise offline."""
    if last_seen is None:
        return "offline"
    age = (now - _utc(last_seen)).total_seconds()
    if age < ONLINE_SECONDS:
        return "online"
    if age < STALE_SECONDS:
        return "stale"
    return "offline"


@router.post("/heartbeat")
def heartbeat(payload: HeartbeatIn, db: Session = Depends(get_db), _collector=Depends(require_collector_key)):
    # Not written to the audit log: one row per collector cycle would drown it.
    now = datetime.now(timezone.utc)
    device = db.query(Device).filter(Device.host == payload.host, Device.source == payload.source).first()
    if device is None:
        device = Device(host=payload.host, source=payload.source, first_seen=now, total_events=0)
        db.add(device)
    device.last_seen = now
    device.total_events = (device.total_events or 0) + payload.events_sent
    db.commit()
    return {"status": "ok"}


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    # Events ingested in the last 5 minutes per (host, source); created_at = ingestion time.
    recent = {
        (host, source): count
        for host, source, count in db.query(Event.host, Event.source, func.count(Event.id))
        .filter(Event.created_at >= now - timedelta(minutes=5))
        .group_by(Event.host, Event.source)
        .all()
    }
    out = [
        DeviceOut(
            host=d.host,
            source=d.source,
            status=device_status(d.last_seen, now),
            last_seen=d.last_seen,
            total_events=d.total_events or 0,
            events_last_5m=recent.get((d.host, d.source), 0),
            simulated=False,
        )
        for d in db.query(Device).order_by(Device.host).all()
    ]
    # Simulated hosts never send heartbeats; list them from their events instead.
    simulated = (
        db.query(Event.host, func.count(Event.id), func.max(Event.created_at))
        .filter(Event.source == "simulated")
        .group_by(Event.host)
        .all()
    )
    for host, count, last in simulated:
        out.append(
            DeviceOut(
                host=host,
                source="simulated",
                status=device_status(last, now),
                last_seen=last,
                total_events=count,
                events_last_5m=recent.get((host, "simulated"), 0),
                simulated=True,
            )
        )
    return out
