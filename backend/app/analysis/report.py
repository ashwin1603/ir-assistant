"""Report helpers: plain-language executive summary and the ATT&CK table.

Built only from rule results (timeline, risk level, actions), not from the AI,
so both report views work even when no AI analysis has been run.
"""

from app.detection.attack_map import TACTICS, TECHNIQUE_NAMES

# What each ATT&CK tactic means, in words a non-technical reader understands.
TACTIC_PLAIN: dict[str, str] = {
    "Credential Access": "Someone tried to guess or steal account passwords.",
    "Execution": "Suspicious commands or scripts were run on the machine.",
    "Defense Evasion": "The activity tried to hide itself or weaken security controls.",
    "Persistence": "Changes were made that could let an attacker keep access to the machine.",
    "Discovery": "Someone gathered information about the machine and its user accounts.",
    "Impact": "Actions were taken that could damage the system or block recovery.",
    "Command and Control": "Files or tools were downloaded from outside the machine.",
    "Lateral Movement": "Remote access to the machine was used.",
}

IMPACT_PLAIN: dict[str, str] = {
    "Low": "Low business impact. The activity is unusual but shows no clear sign of an attack.",
    "Medium": "Moderate impact. The activity needs review by an analyst within the working day.",
    "High": "High impact. The activity looks like a real attack in progress and needs prompt response.",
    "Critical": "Critical impact. Strong signs of compromise; respond immediately and consider isolating the host.",
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
    """The first few actions an analyst has not rejected (approved first, then pending)."""
    order = {"approved": 0, "pending": 1}
    kept = [a for a in actions if a.status in order]
    return sorted(kept, key=lambda a: order[a.status])[:TOP_ACTIONS]


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
