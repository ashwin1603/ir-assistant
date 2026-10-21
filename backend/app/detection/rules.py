"""Data-driven, Sigma-style detection rules. Add new rules here, not in engine.py."""

import re
from dataclasses import dataclass, field

from app.models import Event


@dataclass(frozen=True)
class Rule:
    name: str
    technique_ids: tuple[str, ...]
    severity: int  # 1-10
    confidence: float  # 0-1
    event_ids: tuple[int, ...]
    kind: str = "filter"  # "filter" -> one detection per matching event; "cluster" -> group matching events
    window_minutes: int | None = None
    min_count: int | None = None
    group_by: tuple[str, ...] = ()


def _is_encoded_powershell(event: Event) -> bool:
    text = event.command_line or ""
    return bool(re.search(r"-enc(odedcommand)?\b", text, re.IGNORECASE))


_SCRIPTBLOCK_PATTERNS = (
    r"invoke-expression",
    r"downloadstring",
    r"frombase64string",
    r"\biex\b",
)


def _is_suspicious_scriptblock(event: Event) -> bool:
    text = event.command_line or ""
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in _SCRIPTBLOCK_PATTERNS)


def _is_admin_group_add(event: Event) -> bool:
    text = event.message or ""
    return "administrators" in text.lower()


_TRUSTED_PATH_MARKERS = ("program files", "system32", "syswow64")


def _is_service_outside_trusted_paths(event: Event) -> bool:
    text = f"{event.process or ''} {event.command_line or ''}".lower()
    if not text.strip():
        return False
    return not any(marker in text for marker in _TRUSTED_PATH_MARKERS)


_DISCOVERY_PATTERNS = (
    r"\bwhoami\b",
    r"\bnet\s+(user|group|localgroup)\b",
    r"\bipconfig\b",
    r"\bsysteminfo\b",
)


def _is_discovery_command(event: Event) -> bool:
    text = f"{event.process or ''} {event.command_line or ''}"
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in _DISCOVERY_PATTERNS)


# Rules with no predicate match on event_id alone.
PREDICATES: dict[str, callable] = {
    "Encoded PowerShell command": _is_encoded_powershell,
    "Suspicious PowerShell script block": _is_suspicious_scriptblock,
    "User added to local Administrators": _is_admin_group_add,
    "New service installed outside trusted paths": _is_service_outside_trusted_paths,
    "Discovery command burst": _is_discovery_command,
}

RULES: tuple[Rule, ...] = (
    Rule(
        name="Brute force logon",
        technique_ids=("T1110",),
        severity=6,
        confidence=0.9,
        event_ids=(4625,),
        kind="cluster",
        window_minutes=5,
        min_count=5,
        group_by=("host", "user"),
    ),
    Rule(
        name="Encoded PowerShell command",
        technique_ids=("T1059.001", "T1027"),
        severity=7,
        confidence=0.8,
        event_ids=(4688,),
    ),
    Rule(
        name="Suspicious PowerShell script block",
        technique_ids=("T1059.001",),
        severity=6,
        confidence=0.5,
        event_ids=(4104,),
    ),
    Rule(
        name="Local user account created",
        technique_ids=("T1136.001",),
        severity=5,
        confidence=0.6,
        event_ids=(4720,),
    ),
    Rule(
        name="User added to local Administrators",
        technique_ids=("T1098",),
        severity=8,
        confidence=0.9,
        event_ids=(4732,),
    ),
    Rule(
        name="Scheduled task created",
        technique_ids=("T1053.005",),
        severity=6,
        confidence=0.6,
        event_ids=(4698,),
    ),
    Rule(
        name="New service installed outside trusted paths",
        technique_ids=("T1543.003",),
        severity=7,
        confidence=0.6,
        event_ids=(7045,),
    ),
    Rule(
        name="Security/System event log cleared",
        technique_ids=("T1070.001",),
        severity=9,
        confidence=0.95,
        event_ids=(1102, 104),
    ),
    Rule(
        name="Discovery command burst",
        technique_ids=("T1033", "T1087", "T1082"),
        severity=4,
        confidence=0.6,
        event_ids=(4688,),
        kind="cluster",
        window_minutes=2,
        min_count=2,
        group_by=("host",),
    ),
)
