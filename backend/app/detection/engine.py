import json
import uuid
from datetime import timedelta

from sqlalchemy.orm import Session

from app.analysis.incidents import group_into_incidents
from app.analysis.risk import compute_risk
from app.detection.attack_map import tactics_for
from app.detection.rules import PREDICATES, RULES, Rule
from app.models import Detection, Event, Incident


def _cluster_events(events: list[Event], window_minutes: int, min_count: int, group_by: tuple[str, ...]) -> list[list[Event]]:
    groups: dict[tuple, list[Event]] = {}
    for event in events:
        key = tuple(getattr(event, field) for field in group_by)
        groups.setdefault(key, []).append(event)

    clusters: list[list[Event]] = []
    for group_events in groups.values():
        group_events.sort(key=lambda e: e.timestamp)
        i, n = 0, len(group_events)
        while i < n:
            window_end = group_events[i].timestamp + timedelta(minutes=window_minutes)
            j = i
            while j < n and group_events[j].timestamp <= window_end:
                j += 1
            cluster = group_events[i:j]
            if len(cluster) >= min_count:
                clusters.append(cluster)
                i = j
            else:
                i += 1
    return clusters


# Detection/incident ids are content-addressed (not random) so that re-running
# detection on an unchanged set of events yields the same ids every time -
# the API recomputes on every GET, and clients hold onto ids across requests.
NAMESPACE = uuid.UUID("5c3f8f2a-6b1b-4c2a-9e8d-1b9f2a7d4e60")


def _build_detection(rule: Rule, matched_events: list[Event]) -> Detection:
    matched_ids = sorted(e.id for e in matched_events)
    count = len(matched_ids)
    score, level = compute_risk(rule.severity, rule.confidence, count)
    detection_id = str(uuid.uuid5(NAMESPACE, f"detection|{rule.name}|{','.join(matched_ids)}"))
    return Detection(
        id=detection_id,
        rule_name=rule.name,
        technique_ids=json.dumps(list(rule.technique_ids)),
        tactics=json.dumps(tactics_for(list(rule.technique_ids))),
        severity=rule.severity,
        confidence=rule.confidence,
        host=matched_events[0].host,
        matched_event_ids=json.dumps(matched_ids),
        event_count=count,
        first_seen=min(e.timestamp for e in matched_events),
        last_seen=max(e.timestamp for e in matched_events),
        risk_score=score,
        risk_level=level,
    )


def run_detection(db: Session) -> None:
    """Recompute all detections and incidents from the current events table."""
    events = db.query(Event).order_by(Event.timestamp.asc()).all()

    detections: list[Detection] = []
    for rule in RULES:
        candidates = [e for e in events if e.event_id in rule.event_ids]
        predicate = PREDICATES.get(rule.name)
        if predicate:
            candidates = [e for e in candidates if predicate(e)]

        if rule.kind == "filter":
            by_host: dict[str, list[Event]] = {}
            for event in candidates:
                by_host.setdefault(event.host, []).append(event)
            detections.extend(_build_detection(rule, group) for group in by_host.values())
        else:
            clusters = _cluster_events(candidates, rule.window_minutes, rule.min_count, rule.group_by)
            detections.extend(_build_detection(rule, cluster) for cluster in clusters)

    incidents = group_into_incidents(detections)

    db.query(Detection).delete()
    db.query(Incident).delete()
    db.add_all(incidents)
    db.add_all(detections)
    db.commit()
