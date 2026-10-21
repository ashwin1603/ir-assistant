import json
import subprocess

# Reading Security requires an elevated process; System and the PowerShell
# operational log are usually readable without elevation, but we run everything
# from the same elevated script for simplicity (see scripts/collector.py).
CHANNELS: dict[str, list[int]] = {
    "Security": [4625, 4688, 4720, 4732, 4698, 1102],
    "Microsoft-Windows-PowerShell/Operational": [4104],
    "System": [7045, 104],
}

# 4688 (process creation) is far noisier than the other rule events, so it would
# starve rarer events (4625, 4720, 4698, ...) out of a shared -MaxEvents window.
# Each event id gets its own budget instead.
DEFAULT_MAX_EVENTS = 500
EVENT_MAX_EVENTS: dict[int, int] = {4688: 200}


def max_events_for(event_id: int) -> int:
    return EVENT_MAX_EVENTS.get(event_id, DEFAULT_MAX_EVENTS)


def _build_script(channel: str, event_ids: list[int], max_events: int) -> str:
    ids = ",".join(str(i) for i in event_ids)
    return (
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='{channel}'; Id={ids}}} "
        f"-MaxEvents {max_events} -ErrorAction SilentlyContinue; "
        "if ($events) { "
        "$events | ForEach-Object { "
        "[PSCustomObject]@{ "
        "RecordId = $_.RecordId; "
        "TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); "
        "Id = $_.Id; "
        "LogName = $_.LogName; "
        "ProviderName = $_.ProviderName; "
        "MachineName = $_.MachineName; "
        "Message = $_.Message; "
        "Properties = @($_.Properties | ForEach-Object { $_.Value }) "
        "} } | ConvertTo-Json -Depth 5 "
        "} else { '[]' }"
    )


def fetch_events(channel: str, event_ids: list[int], max_events: int = 200) -> list[dict]:
    script = _build_script(channel, event_ids, max_events)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Get-WinEvent failed for '{channel}': {result.stderr.strip()}")

    output = result.stdout.strip() or "[]"
    data = json.loads(output)
    if isinstance(data, dict):
        data = [data]
    return data


def fetch_all() -> list[dict]:
    events: list[dict] = []
    for channel, event_ids in CHANNELS.items():
        for event_id in event_ids:
            events.extend(fetch_events(channel, [event_id], max_events_for(event_id)))
    return events
