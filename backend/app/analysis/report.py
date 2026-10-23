"""Report helpers: plain-language executive summary and the ATT&CK table.

Built only from rule results (timeline, risk level, actions), not from the AI,
so both report views work even when no AI analysis has been run.

Wording rule: say only what the evidence shows. Rules match commands and log
entries, so the text says what was seen or attempted, not what succeeded.
"""

import json

from sqlalchemy.orm import Session

from app.detection.attack_map import TACTICS, TECHNIQUE_NAMES
from app.models import Detection, Event

# What each ATT&CK tactic means, in words a non-technical reader understands.
TACTIC_PLAIN: dict[str, str] = {
    "Credential Access": "There were attempts to guess or read account passwords.",
    "Execution": "Suspicious commands or scripts were run on the machine.",
    "Defense Evasion": "Actions were seen that can hide activity or weaken security controls.",
    "Persistence": "Changes were made that could let an attacker keep access to the machine.",
    "Discovery": "Commands that gather information about the machine and its user accounts were run.",
    "Impact": "Commands were run that could damage the system or block recovery.",
    "Command and Control": "Commands that can download files or tools from outside the machine were run.",
    "Lateral Movement": "Remote access to the machine was enabled.",
}

IMPACT_PLAIN: dict[str, str] = {
    "Low": "Low business impact. The activity is unusual but shows no clear sign of an attack.",
    "Medium": "Moderate impact. The activity needs review by an analyst within the working day.",
    "High": "High impact. The activity matches known attack techniques and needs prompt response.",
    "Critical": "Critical impact. Several strong signs of possible compromise; respond immediately and consider isolating the host.",
}

TOP_ACTIONS = 3


def what_happened(timeline: list[dict]) -> list[str]:
    """One sentence per tactic, in the order the tactics first appeared."""
    sentences: list[str] = []
    for entry in sorted(timeline, key=lambda e: e["first_seen"]):
        for tactic in entry["tactics"]:
            sentence = TACTIC_PLAIN.get(tactic, f"Activity related to {tactic} was detected.")
            if sentence not in sentences:
                sentences.append(sentence)
    return sentences


def impact_text(risk_level: str) -> str:
    return IMPACT_PLAIN.get(risk_level, "Impact could not be assessed.")


def top_actions(actions: list) -> list:
    """The first few actions with their status: approved first, then pending, then rejected.
    Rejected ones are kept so the reader sees what the analyst decided against."""
    order = {"approved": 0, "pending": 1, "rejected": 2}
    return sorted(actions, key=lambda a: order.get(a.status, 3))[:TOP_ACTIONS]


def is_simulated(db: Session, incident_id: str) -> bool:
    """True if any evidence event of this incident came from the attack simulator."""
    event_ids: set[str] = set()
    for d in db.query(Detection).filter(Detection.incident_id == incident_id).all():
        event_ids.update(json.loads(d.matched_event_ids))
    if not event_ids:
        return False
    return db.query(Event).filter(Event.id.in_(event_ids), Event.source == "simulated").first() is not None


def attack_table(timeline: list[dict]) -> list[dict]:
    """One row per technique: name, tactic, which rules fired, and the evidence ids."""
    rows: dict[str, dict] = {}
    for entry in timeline:
        for technique_id in entry["technique_ids"]:
            row = rows.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": TECHNIQUE_NAMES.get(technique_id, "Unknown"),
                    "tactic": TACTICS.get(technique_id, "Unknown"),
                    "rule_names": [],
                    "detection_count": 0,
                    "event_ids": [],
                },
            )
            row["detection_count"] += 1
            if entry["rule_name"] not in row["rule_names"]:
                row["rule_names"].append(entry["rule_name"])
            row["event_ids"].extend(i for i in entry["event_ids"] if i not in row["event_ids"])
    return sorted(rows.values(), key=lambda r: r["technique_id"])
