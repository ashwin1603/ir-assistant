BASE_EVENT = {
    "id": "a0000000-0000-0000-0000-000000000000",
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
    events = []
    for i in range(5):
        events.append(
            {
                **BASE_EVENT,
                "id": f"a000000{i}-0000-0000-0000-000000000000",
                "timestamp": f"2026-10-21T05:00:0{i}+00:00",
            }
        )
    return events


def _auth_headers(client, seed_users):
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_list_detections_requires_auth(client):
    resp = client.get("/api/detections")
    assert resp.status_code == 401


def test_list_incidents_requires_auth(client):
    resp = client.get("/api/incidents")
    assert resp.status_code == 401


def test_detections_and_incidents_populated_after_ingest(client, seed_users):
    client.post(
        "/api/events/ingest",
        json={"events": _brute_force_events()},
        headers={"X-Collector-Key": "test-collector-key"},
    )
    headers = _auth_headers(client, seed_users)

    detections_resp = client.get("/api/detections", headers=headers)
    assert detections_resp.status_code == 200
    detections = detections_resp.json()
    assert len(detections) == 1
    detection = detections[0]
    assert detection["rule_name"] == "Brute force logon"
    assert detection["technique_ids"] == ["T1110"]
    assert detection["event_count"] == 5
    assert len(detection["matched_event_ids"]) == 5

    incidents_resp = client.get("/api/incidents", headers=headers)
    assert incidents_resp.status_code == 200
    incidents = incidents_resp.json()
    assert len(incidents) == 1
    incident_id = incidents[0]["id"]

    detail_resp = client.get(f"/api/incidents/{incident_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert len(detail["timeline"]) == 1
    assert detail["timeline"][0]["rule_name"] == "Brute force logon"
    assert len(detail["timeline"][0]["event_ids"]) == 5


def test_get_incident_not_found(client, seed_users):
    headers = _auth_headers(client, seed_users)
    resp = client.get("/api/incidents/does-not-exist", headers=headers)
    assert resp.status_code == 404
