"""ATT&CK technique -> tactic lookup used to tag detections."""

TACTICS: dict[str, str] = {
    "T1110": "Credential Access",
    "T1059.001": "Execution",
    "T1027": "Defense Evasion",
    "T1136.001": "Persistence",
    "T1098": "Persistence",
    "T1053.005": "Persistence",
    "T1543.003": "Persistence",
    "T1070.001": "Defense Evasion",
    "T1033": "Discovery",
    "T1087": "Discovery",
    "T1082": "Discovery",
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1110": "Brute Force",
    "T1059.001": "PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1136.001": "Local Account",
    "T1098": "Account Manipulation",
    "T1053.005": "Scheduled Task/Job",
    "T1543.003": "Windows Service",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1033": "System Owner/User Discovery",
    "T1087": "Account Discovery",
    "T1082": "System Information Discovery",
}


def tactics_for(technique_ids: list[str]) -> list[str]:
    seen = []
    for technique_id in technique_ids:
        tactic = TACTICS.get(technique_id, "Unknown")
        if tactic not in seen:
            seen.append(tactic)
    return seen
