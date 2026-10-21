"""Group nearby detections on the same host into incidents."""

import uuid
from collections import defaultdict
from datetime import timedelta

from app.analysis.risk import risk_level
from app.models import Detection, Incident

GAP = timedelta(minutes=30)


def group_into_incidents(detections: list[Detection]) -> list[Incident]:
    """Mutates detections in place to set incident_id, returns the Incident rows."""
    by_host: dict[str, list[Detection]] = defaultdict(list)
    for detection in detections:
        by_host[detection.host].append(detection)

    incidents: list[Incident] = []
    for host, host_detections in by_host.items():
        host_detections.sort(key=lambda d: d.first_seen)
        current: list[Detection] = []
        window_end = None
        for detection in host_detections:
            if current and detection.first_seen <= window_end:
                current.append(detection)
                window_end = max(window_end, detection.last_seen) + GAP
            else:
                if current:
                    incidents.append(_build_incident(host, current))
                current = [detection]
                window_end = detection.last_seen + GAP
        if current:
            incidents.append(_build_incident(host, current))
    return incidents


#  must match app.detection.engine.NAMESPACE - both derive content-addressed
# ids so a rerun of detection on unchanged events keeps the same incident id.
NAMESPACE = uuid.UUID("5c3f8f2a-6b1b-4c2a-9e8d-1b9f2a7d4e60")


def _build_incident(host: str, detections: list[Detection]) -> Incident:
    detection_ids = sorted(detection.id for detection in detections)
    incident_id = str(uuid.uuid5(NAMESPACE, f"incident|{host}|{','.join(detection_ids)}"))
    for detection in detections:
        detection.incident_id = incident_id
    score = max(detection.risk_score for detection in detections)
    return Incident(
        id=incident_id,
        host=host,
        started_at=min(detection.first_seen for detection in detections),
        ended_at=max(detection.last_seen for detection in detections),
        risk_score=score,
        risk_level=risk_level(score),
        detection_count=len(detections),
    )
