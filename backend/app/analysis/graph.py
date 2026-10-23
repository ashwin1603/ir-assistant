from collections import Counter

from sqlalchemy.orm import Session

from app.analysis.timeline import build_timeline
from app.models import Event, Incident


def _main_user(db: Session, event_ids: list[str]) -> str | None:
    """Most common user across the incident's matched events, if any."""
    if not event_ids:
        return None
    users = [u for (u,) in db.query(Event.user).filter(Event.id.in_(event_ids)).all() if u]
    return Counter(users).most_common(1)[0][0] if users else None


def build_graph(db: Session, incident: Incident) -> dict:
    """Attack graph: host (and user) -> detections in time order.

    Edges: host->first detection, then a chain between consecutive detections.
    A chain edge between two detections with the same primary tactic is marked
    "same_tactic" so the UI can show them as one group.
    """
    timeline = build_timeline(db, incident.id)
    host_id = f"host:{incident.host}"
    nodes = [{"id": host_id, "type": "host", "label": incident.host}]
    edges = []

    all_event_ids = [eid for entry in timeline for eid in entry["event_ids"]]
    user = _main_user(db, all_event_ids)
    if user:
        user_id = f"user:{user}"
        nodes.append({"id": user_id, "type": "user", "label": user})
        edges.append({"source": user_id, "target": host_id, "kind": "account"})

    previous = None
    for entry in timeline:
        tactic = entry["tactics"][0] if entry["tactics"] else "unknown"
        technique = entry["technique_ids"][0] if entry["technique_ids"] else None
        node = {
            "id": entry["detection_id"],
            "type": "detection",
            "label": entry["rule_name"],
            "rule": entry["rule_name"],
            "technique": technique,
            "technique_ids": entry["technique_ids"],
            "tactic": tactic,
            "risk_score": entry["risk_score"],
            "risk_level": entry["risk_level"],
            "first_seen": entry["first_seen"],
        }
        nodes.append(node)
        if previous is None:
            edges.append({"source": host_id, "target": node["id"], "kind": "start"})
        else:
            kind = "same_tactic" if previous["tactic"] == tactic else "sequence"
            edges.append({"source": previous["id"], "target": node["id"], "kind": kind})
        previous = node

    return {"incident_id": incident.id, "nodes": nodes, "edges": edges}
