from app.config import settings
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


def _brute_force_events():
    return [
        {**BASE_EVENT, "id": f"a000000{i}-0000-0000-0000-000000000000", "timestamp": f"2026-10-21T05:00:0{i}+00:00"}
        for i in range(5)
    ]


def _login(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _seed_pending_action(client, seed_users, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "template")
    client.post(
        "/api/events/ingest",
        json={"events": _brute_force_events()},
        headers={"X-Collector-Key": "test-collector-key"},
    )
    analyst_headers = _login(client, "test_analyst", "TestAnalystPass123!")
    incident_id = client.get("/api/incidents", headers=analyst_headers).json()[0]["id"]
    client.post(f"/api/incidents/{incident_id}/analyze", headers=analyst_headers)
    action_id = client.get("/api/actions", headers=analyst_headers).json()[0]["id"]
    return action_id, analyst_headers


def test_list_actions_requires_auth(client):
    resp = client.get("/api/actions")
    assert resp.status_code == 401


def test_approve_requires_auth(client):
    resp = client.post("/api/actions/does-not-exist/approve")
    assert resp.status_code == 401


def test_approve_forbidden_for_viewer(client, seed_users):
    headers = _login(client, "test_viewer", "TestViewerPass123!")
    resp = client.post("/api/actions/does-not-exist/approve", headers=headers)
    assert resp.status_code == 403


def test_approve_404_for_unknown_action(client, seed_users):
    headers = _login(client, "test_analyst", "TestAnalystPass123!")
    resp = client.post("/api/actions/does-not-exist/approve", headers=headers)
    assert resp.status_code == 404


def test_analyze_populates_pending_actions(client, seed_users, monkeypatch):
    action_id, headers = _seed_pending_action(client, seed_users, monkeypatch)
    actions = client.get("/api/actions", headers=headers).json()
    assert all(a["status"] == "pending" for a in actions)
    assert any(a["id"] == action_id for a in actions)


def test_approve_action_is_simulated_and_audited(client, seed_users, monkeypatch, db_session):
    action_id, headers = _seed_pending_action(client, seed_users, monkeypatch)

    resp = client.post(f"/api/actions/{action_id}/approve", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["decided_by"] == "test_analyst"

    entry = db_session.query(AuditLog).filter(AuditLog.action == "action_approved").one()
    assert "simulated, not executed" in entry.detail


def test_reject_action(client, seed_users, monkeypatch):
    action_id, headers = _seed_pending_action(client, seed_users, monkeypatch)

    resp = client.post(f"/api/actions/{action_id}/reject", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


def test_cannot_decide_an_action_twice(client, seed_users, monkeypatch):
    action_id, headers = _seed_pending_action(client, seed_users, monkeypatch)

    client.post(f"/api/actions/{action_id}/approve", headers=headers)
    resp = client.post(f"/api/actions/{action_id}/reject", headers=headers)
    assert resp.status_code == 409
