"""Live-update stream: header auth only, signal-only payload, per-user cap, short-lived."""

import json

import app.routes.stream as stream_routes
from app.models import Detection

COLLECTOR = {"X-Collector-Key": "test-collector-key"}
PASSWORDS = {"viewer": "TestViewerPass123!", "analyst": "TestAnalystPass123!"}
SIGNAL_KEYS = {"events", "detections", "incidents", "pending_actions", "latest_event_id", "latest_detection_id"}

EVENT = {
    "id": "66666666-6666-6666-6666-666666666666",
    "source": "simulated",
    "host": "SIM-WS01",
    "timestamp": "2026-10-21T05:00:00+00:00",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688,
    "user": "victim",
    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "command_line": r"powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\stage2.ps1",
    "parent_process": None,
    "src_ip": None,
    "logon_type": None,
    "message": "A new process has been created. SecretMessageMarker",
    "raw": "{}",
}


def _headers(client, role):
    token = client.post("/api/auth/login", json={"username": f"test_{role}", "password": PASSWORDS[role]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _signals(body: str) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in body.splitlines() if line.startswith("data: ")]


def test_stream_requires_a_bearer_token(client, seed_users):
    assert client.get("/api/stream").status_code == 401
    # A token in the query string is not accepted: only the Authorization header counts.
    token = client.post("/api/auth/login", json={"username": "test_viewer", "password": PASSWORDS["viewer"]}).json()["access_token"]
    assert client.get("/api/stream", params={"token": token}).status_code == 401
    assert client.get("/api/stream", params={"access_token": token}).status_code == 401


def test_viewer_stream_has_only_counts_and_ids(client, seed_users):
    assert client.post("/api/events/ingest", json={"events": [EVENT]}, headers=COLLECTOR).status_code == 201
    resp = client.get("/api/stream", headers=_headers(client, "viewer"))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    signals = _signals(resp.text)
    assert signals, resp.text
    for signal in signals:
        assert set(signal) == SIGNAL_KEYS
    assert signals[0]["events"] == 1 and signals[0]["latest_event_id"] == EVENT["id"]
    for secret in ("Bypass", "stage2.ps1", "SecretMessageMarker", "powershell", "victim", "SIM-WS01"):
        assert secret not in resp.text


def test_stream_never_runs_detection(client, seed_users, db_session):
    # A log-cleared event (1102) becomes a detection as soon as detection runs.
    cleared = {**EVENT, "event_id": 1102, "command_line": None, "message": "The audit log was cleared."}
    assert client.post("/api/events/ingest", json={"events": [cleared]}, headers=COLLECTOR).status_code == 201
    signals = _signals(client.get("/api/stream", headers=_headers(client, "analyst")).text)
    assert signals[-1]["events"] == 1 and signals[-1]["detections"] == 0
    assert db_session.query(Detection).count() == 0
    # The list route still runs it, so the rule itself does fire on this event.
    assert len(client.get("/api/detections", headers=_headers(client, "analyst")).json()) >= 1


def test_per_user_stream_cap(client, seed_users):
    headers = _headers(client, "viewer")
    slots = [stream_routes.acquire_slot("test_viewer") for _ in range(stream_routes.MAX_STREAMS_PER_USER)]
    try:
        assert all(slots)
        assert stream_routes.acquire_slot("test_viewer") is None
        assert client.get("/api/stream", headers=headers).status_code == 429
        # Another user is not affected by the viewer's cap.
        assert client.get("/api/stream", headers=_headers(client, "analyst")).status_code == 200
    finally:
        for slot in slots:
            stream_routes.release_slot("test_viewer", slot)
    assert client.get("/api/stream", headers=headers).status_code == 200


def test_finished_stream_releases_its_slot(client, seed_users):
    assert client.get("/api/stream", headers=_headers(client, "analyst")).status_code == 200
    assert stream_routes.open_streams("test_analyst") == 0
