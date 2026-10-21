import json
import uuid

# Property index -> field, per the documented EventData layout for each event id.
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
FIELD_MAP: dict[int, dict[str, int]] = {
    4625: {"user": 5, "logon_type": 10, "process": 18, "src_ip": 19},  # failed logon
    4688: {"user": 1, "process": 5, "command_line": 8, "parent_process": 13},  # process creation
    4720: {"user": 4},  # user account created (subject = actor)
    4732: {"user": 6},  # member added to local group (subject = actor)
    4698: {"user": 1, "command_line": 5},  # scheduled task created
    1102: {"user": 1},  # security log cleared
    104: {"user": 2},  # system log cleared (best-effort field layout)
    7045: {"process": 0, "command_line": 1, "user": 4},  # new service installed
    4104: {"command_line": 2},  # PowerShell script block logging
}


def _prop(properties: list | None, index: int | None) -> str | None:
    if index is None or not properties:
        return None
    if index < 0 or index >= len(properties):
        return None
    value = properties[index]
    return None if value is None else str(value)


def normalize_event(raw_event: dict, host: str, source: str = "agent") -> dict:
    event_id = int(raw_event["Id"])
    properties = raw_event.get("Properties") or []
    field_map = FIELD_MAP.get(event_id, {})

    process = _prop(properties, field_map.get("process"))
    if event_id == 4104:
        process = "powershell.exe"

    record_id = raw_event.get("RecordId")

    return {
        "id": str(uuid.uuid4()),
        "record_id": int(record_id) if record_id is not None else None,
        "source": source,
        "host": host or raw_event.get("MachineName") or "unknown",
        "timestamp": raw_event["TimeCreated"],
        "channel": raw_event.get("LogName", ""),
        "provider": raw_event.get("ProviderName") or "",
        "event_id": event_id,
        "user": _prop(properties, field_map.get("user")),
        "process": process,
        "command_line": _prop(properties, field_map.get("command_line")),
        "parent_process": _prop(properties, field_map.get("parent_process")),
        "src_ip": _prop(properties, field_map.get("src_ip")),
        "logon_type": _prop(properties, field_map.get("logon_type")),
        "message": raw_event.get("Message") or "",
        "raw": json.dumps(raw_event),
    }


def normalize_events(raw_events: list[dict], host: str, source: str = "agent") -> list[dict]:
    return [normalize_event(event, host, source) for event in raw_events]
