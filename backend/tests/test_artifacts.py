import hashlib

from app.analysis.artifacts import iocs_to_csv
from app.models import AuditLog

COLLECTOR = {"X-Collector-Key": "test-collector-key"}
ENCODED_CMD = "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"

BASE_EVENT = {
    "source": "agent",
    "host": "HOST-A",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4625,
    "user": "fakeuser",
    "process": None,
    "command_line": None,
    "parent_process": None,
    "src_ip": "10.0.0.5",
    "logon_type": "3",
    "message": "An account failed to log on.",
    "raw": "{}",
}


def _login(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _analyst(client):
    return _login(client, "test_analyst", "TestAnalystPass123!")


def _seed_incident(client, headers):
    events = [
        {**BASE_EVENT, "id": f"d000000{i}-0000-0000-0000-000000000000", "timestamp": f"2026-10-21T05:00:0{i}+00:00"}
        for i in range(5)
    ]
    events.append(
        {
            **BASE_EVENT,
            "id": "d0000009-0000-0000-0000-000000000000",
            "timestamp": "2026-10-21T05:01:00+00:00",
            "event_id": 4688,
            "user": "SYSTEM",
            "src_ip": "127.0.0.1",
            "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "command_line": ENCODED_CMD,
            "message": "A new process has been created.",
        }
    )
    client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR)
    return client.get("/api/incidents", headers=headers).json()[0]["id"]


def test_iocs_extracted_from_evidence(client, seed_users):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)

    iocs = client.get(f"/api/incidents/{incident_id}/iocs", headers=headers).json()
    by_type = {(i["type"], i["value"]) for i in iocs}

    assert ("ip", "10.0.0.5") in by_type
    assert ("user", "fakeuser") in by_type
    assert ("process", "C:\\Windows\\System32\\cmd.exe") in by_type
    assert ("cmdline_sha256", hashlib.sha256(ENCODED_CMD.encode()).hexdigest()) in by_type
    # Loopback and built-in accounts are noise, not indicators.
    assert ("ip", "127.0.0.1") not in by_type
    assert ("user", "SYSTEM") not in by_type
    ip_ioc = next(i for i in iocs if i["type"] == "ip")
    assert ip_ioc["event_count"] == 5


def test_ioc_csv_download_and_audit(client, seed_users, db_session):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)

    resp = client.get(f"/api/incidents/{incident_id}/iocs?format=csv", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.text.splitlines()[0] == "type,value,event_count,event_ids"
    assert "10.0.0.5" in resp.text

    log = db_session.query(AuditLog).filter(AuditLog.action == "ioc_download").one()
    assert "format=csv" in log.detail
    assert log.actor == "test_analyst"


def test_csv_formula_injection_neutralised():
    csv_text = iocs_to_csv([{"type": "user", "value": "=cmd|'/c calc'!A1", "event_count": 1, "event_ids": ["x"]}])
    assert "'=cmd" in csv_text


def test_firewall_script_is_text_with_review_banner(client, seed_users, db_session):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)

    resp = client.get(f"/api/incidents/{incident_id}/scripts/firewall", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "REVIEW BEFORE USE" in resp.text
    assert "-RemoteAddress 10.0.0.5 -Action Block" in resp.text
    assert "127.0.0.1" not in resp.text

    resp = client.get(f"/api/incidents/{incident_id}/scripts/isolation", headers=headers)
    assert resp.status_code == 200
    assert "REVIEW BEFORE USE" in resp.text
    assert "DefaultOutboundAction Block" in resp.text

    kinds = [log.detail for log in db_session.query(AuditLog).filter(AuditLog.action == "script_download")]
    assert len(kinds) == 2


def test_malicious_ip_field_never_reaches_script(client, seed_users):
    headers = _analyst(client)
    events = [
        {
            **BASE_EVENT,
            "id": f"e000000{i}-0000-0000-0000-000000000000",
            "timestamp": f"2026-10-21T06:00:0{i}+00:00",
            "src_ip": "1.2.3.4; Remove-Item C:\\ -Recurse",
        }
        for i in range(5)
    ]
    client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR)
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]

    script = client.get(f"/api/incidents/{incident_id}/scripts/firewall", headers=headers).text
    assert "Remove-Item C:\\ -Recurse" not in script
    assert "Nothing to block" in script


def test_viewer_gets_iocs_but_not_scripts(client, seed_users):
    analyst = _analyst(client)
    incident_id = _seed_incident(client, analyst)
    viewer = _login(client, "test_viewer", "TestViewerPass123!")

    assert client.get(f"/api/incidents/{incident_id}/iocs", headers=viewer).status_code == 200
    assert client.get(f"/api/incidents/{incident_id}/scripts/firewall", headers=viewer).status_code == 403


def test_artifacts_require_auth_and_valid_input(client, seed_users):
    assert client.get("/api/incidents/x/iocs").status_code == 401
    assert client.get("/api/incidents/x/scripts/firewall").status_code == 401

    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)
    assert client.get(f"/api/incidents/{incident_id}/iocs?format=xml", headers=headers).status_code == 422
    assert client.get(f"/api/incidents/{incident_id}/scripts/wipe", headers=headers).status_code == 422
    assert client.get("/api/incidents/nope/iocs", headers=headers).status_code == 404
