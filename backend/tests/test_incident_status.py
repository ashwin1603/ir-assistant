from app.models import AuditLog

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
COLLECTOR = {"X-Collector-Key": "test-collector-key"}


def _login(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _seed_incident(client):
    events = [
        {**BASE_EVENT, "id": f"b000000{i}-0000-0000-0000-000000000000", "timestamp": f"2026-10-21T05:00:0{i}+00:00"}
        for i in range(5)
    ]
    client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR)


def _analyst(client):
    return _login(client, "test_analyst", "TestAnalystPass123!")


def test_new_incident_defaults_to_new(client, seed_users):
    _seed_incident(client)
    incidents = client.get("/api/incidents", headers=_analyst(client)).json()
    assert incidents[0]["status"] == "new"


def test_viewer_can_read_but_not_write(client, seed_users):
    _seed_incident(client)
    headers = _login(client, "test_viewer", "TestViewerPass123!")
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]

    assert client.get(f"/api/incidents/{incident_id}", headers=headers).status_code == 200
    resp = client.put(f"/api/incidents/{incident_id}/status", json={"status": "closed"}, headers=headers)
    assert resp.status_code == 403
    resp = client.post(f"/api/incidents/{incident_id}/notes", json={"text": "hi"}, headers=headers)
    assert resp.status_code == 403


def test_write_requires_auth(client):
    assert client.put("/api/incidents/x/status", json={"status": "closed"}).status_code == 401
    assert client.post("/api/incidents/x/notes", json={"text": "hi"}).status_code == 401


def test_invalid_status_and_empty_note_rejected(client, seed_users):
    _seed_incident(client)
    headers = _analyst(client)
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]

    resp = client.put(f"/api/incidents/{incident_id}/status", json={"status": "pwned"}, headers=headers)
    assert resp.status_code == 422
    resp = client.post(f"/api/incidents/{incident_id}/notes", json={"text": ""}, headers=headers)
    assert resp.status_code == 422


def test_unknown_incident_404(client, seed_users):
    resp = client.put("/api/incidents/nope/status", json={"status": "closed"}, headers=_analyst(client))
    assert resp.status_code == 404


def test_status_and_notes_are_audited(client, seed_users, db_session):
    _seed_incident(client)
    headers = _analyst(client)
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]

    resp = client.put(f"/api/incidents/{incident_id}/status", json={"status": "investigating"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"
    resp = client.post(f"/api/incidents/{incident_id}/notes", json={"text": "secret-ish detail"}, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["author"] == "test_analyst"

    status_log = db_session.query(AuditLog).filter(AuditLog.action == "incident_status").one()
    assert "new -> investigating" in status_log.detail
    note_log = db_session.query(AuditLog).filter(AuditLog.action == "incident_note").one()
    assert "secret-ish detail" not in note_log.detail


def test_status_filter(client, seed_users):
    _seed_incident(client)
    headers = _analyst(client)
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]
    client.put(f"/api/incidents/{incident_id}/status", json={"status": "contained"}, headers=headers)

    assert len(client.get("/api/incidents?status=contained", headers=headers).json()) == 1
    assert client.get("/api/incidents?status=new", headers=headers).json() == []
    assert client.get("/api/incidents?status=bogus", headers=headers).status_code == 422


def test_status_and_notes_survive_regrouping(client, seed_users):
    _seed_incident(client)
    headers = _analyst(client)
    old_id = client.get("/api/incidents", headers=headers).json()[0]["id"]
    client.put(f"/api/incidents/{old_id}/status", json={"status": "investigating"}, headers=headers)
    client.post(f"/api/incidents/{old_id}/notes", json={"text": "brute force from 10.0.0.5"}, headers=headers)

    # A later detection on the same host joins the incident and changes its hash-derived id.
    new_event = {
        **BASE_EVENT,
        "id": "c0000000-0000-0000-0000-000000000000",
        "event_id": 4720,
        "timestamp": "2026-10-21T05:10:00+00:00",
        "message": "A user account was created.",
    }
    client.post("/api/events/ingest", json={"events": [new_event]}, headers=COLLECTOR)

    incidents = client.get("/api/incidents", headers=headers).json()
    assert len(incidents) == 1
    new_id = incidents[0]["id"]
    assert new_id != old_id
    assert incidents[0]["status"] == "investigating"

    detail = client.get(f"/api/incidents/{new_id}", headers=headers).json()
    assert [n["text"] for n in detail["notes"]] == ["brute force from 10.0.0.5"]
