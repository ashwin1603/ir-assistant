SAMPLE_EVENT = {
    "id": "11111111-1111-1111-1111-111111111111",
    "source": "agent",
    "host": "TESTHOST",
    "timestamp": "2026-10-21T05:00:00+00:00",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4625,
    "user": "attacker",
    "process": None,
    "command_line": None,
    "parent_process": None,
    "src_ip": "10.0.0.5",
    "logon_type": "3",
    "message": "An account failed to log on.",
    "raw": "{}",
}


def _other_event(event_id=4688, message="process start"):
    return {**SAMPLE_EVENT, "id": "22222222-2222-2222-2222-222222222222", "event_id": event_id, "message": message, "src_ip": None}


def test_ingest_rejects_missing_key(client):
    resp = client.post("/api/events/ingest", json={"events": [SAMPLE_EVENT]})
    assert resp.status_code == 401


def test_ingest_rejects_wrong_key(client):
    resp = client.post("/api/events/ingest", json={"events": [SAMPLE_EVENT]}, headers={"X-Collector-Key": "wrong"})
    assert resp.status_code == 401


def test_ingest_accepts_correct_key(client):
    resp = client.post("/api/events/ingest", json={"events": [SAMPLE_EVENT]}, headers={"X-Collector-Key": "test-collector-key"})
    assert resp.status_code == 201
    assert resp.json() == {"ingested": 1, "skipped": 0}


def test_ingest_skips_duplicate_record_id_host_channel(client):
    dup_event = {**SAMPLE_EVENT, "record_id": 777}
    headers = {"X-Collector-Key": "test-collector-key"}

    first = client.post("/api/events/ingest", json={"events": [dup_event]}, headers=headers)
    assert first.json() == {"ingested": 1, "skipped": 0}

    retry = {**dup_event, "id": "99999999-0000-0000-0000-000000000000"}
    second = client.post("/api/events/ingest", json={"events": [retry]}, headers=headers)
    assert second.json() == {"ingested": 0, "skipped": 1}


def test_ingest_does_not_dedupe_different_hosts(client):
    event_a = {**SAMPLE_EVENT, "record_id": 777, "host": "HOST-A"}
    event_b = {**SAMPLE_EVENT, "id": "88888888-0000-0000-0000-000000000000", "record_id": 777, "host": "HOST-B"}
    headers = {"X-Collector-Key": "test-collector-key"}

    resp = client.post("/api/events/ingest", json={"events": [event_a, event_b]}, headers=headers)
    assert resp.json() == {"ingested": 2, "skipped": 0}


def test_list_events_requires_auth(client):
    resp = client.get("/api/events")
    assert resp.status_code == 401


def test_list_events_returns_ingested(client, seed_users):
    client.post("/api/events/ingest", json={"events": [SAMPLE_EVENT]}, headers={"X-Collector-Key": "test-collector-key"})
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]

    resp = client.get("/api/events", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["event_id"] == 4625


def test_list_events_filters_by_event_id_and_channel(client, seed_users):
    client.post(
        "/api/events/ingest",
        json={"events": [SAMPLE_EVENT, _other_event()]},
        headers={"X-Collector-Key": "test-collector-key"},
    )
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/events", params={"event_id": 4688}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["event_id"] == 4688


def test_list_events_search_matches_message(client, seed_users):
    client.post(
        "/api/events/ingest",
        json={"events": [SAMPLE_EVENT, _other_event(message="encoded powershell command")]},
        headers={"X-Collector-Key": "test-collector-key"},
    )
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/events", params={"q": "encoded"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert "encoded" in body["items"][0]["message"]


def test_ingest_accepts_large_script_block(client):
    # Real PowerShell 4104 script-block events (profile/module loading) commonly
    # produce multi-KB command_line/raw payloads; the schema must not reject these.
    large_event = {
        **SAMPLE_EVENT,
        "id": "55555555-5555-5555-5555-555555555555",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "event_id": 4104,
        "command_line": "x" * 15000,
        "raw": "y" * 30000,
    }
    resp = client.post("/api/events/ingest", json={"events": [large_event]}, headers={"X-Collector-Key": "test-collector-key"})
    assert resp.status_code == 201


def test_ingest_rejects_oversized_field_without_leaking_value(client):
    huge_event = {**SAMPLE_EVENT, "id": "66666666-6666-6666-6666-666666666666", "message": "x" * 60000}
    resp = client.post("/api/events/ingest", json={"events": [huge_event]}, headers={"X-Collector-Key": "test-collector-key"})
    assert resp.status_code == 422
    body = resp.json()
    assert any(err["type"] == "string_too_long" for err in body["detail"])
    for err in body["detail"]:
        assert "input" not in err
        assert "x" * 100 not in str(err)


def test_list_events_pagination(client, seed_users):
    events = [_other_event(message=f"event {i}") | {"id": f"3333333{i}-3333-3333-3333-333333333333"} for i in range(5)]
    client.post("/api/events/ingest", json={"events": events}, headers={"X-Collector-Key": "test-collector-key"})
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/events", params={"page": 1, "page_size": 2}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2
