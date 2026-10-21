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


# Technique -> recommended mitigations, grounded in ATT&CK mitigation guidance.
# The AI selects from and explains these; it does not invent its own actions.
MITIGATIONS: dict[str, list[str]] = {
    "T1110": [
        "Lock out or disable the account after repeated failed logons",
        "Enforce account lockout policy and strong password policy",
        "Enable MFA for remote and privileged logons",
    ],
    "T1059.001": [
        "Enable PowerShell Script Block Logging and Constrained Language Mode",
        "Restrict execution policy and use AppLocker/WDAC to block unsigned scripts",
        "Terminate the offending process if unauthorized",
    ],
    "T1027": [
        "Decode and inspect the encoded command line for malicious intent",
        "Block execution of base64-encoded command lines via AppLocker/WDAC",
        "Isolate the host for forensic review",
    ],
    "T1136.001": [
        "Verify the new local account was authorized; disable it if not",
        "Review who created the account and why",
        "Audit local Administrators group membership on the host",
    ],
    "T1098": [
        "Remove the unauthorized account from the Administrators group immediately",
        "Reset credentials for the affected account",
        "Review recent privilege escalation events on the host",
    ],
    "T1053.005": [
        "Review the scheduled task's action and trigger; delete if unauthorized",
        "Restrict who can create scheduled tasks via Group Policy",
        "Hunt for persistence via other scheduled tasks on the host",
    ],
    "T1543.003": [
        "Inspect the new service's binary path and signer; stop/delete if malicious",
        "Restrict service installation privileges to administrators only",
        "Scan the host for related malware",
    ],
    "T1070.001": [
        "Treat log clearing as a high-confidence compromise indicator and escalate immediately",
        "Forward logs to a central SIEM so local clearing cannot destroy evidence",
        "Isolate the host pending investigation",
    ],
    "T1033": [
        "Correlate discovery activity with the parent process and user session",
        "Review whether this is expected admin activity or a reconnaissance step",
    ],
    "T1087": [
        "Review whether this is expected admin activity or a reconnaissance step",
        "Monitor for follow-on lateral movement or credential access",
    ],
    "T1082": [
        "Review whether this is expected admin activity or a reconnaissance step",
        "Monitor for follow-on lateral movement or credential access",
    ],
}


def tactics_for(technique_ids: list[str]) -> list[str]:
    seen = []
    for technique_id in technique_ids:
        tactic = TACTICS.get(technique_id, "Unknown")
        if tactic not in seen:
            seen.append(tactic)
    return seen
