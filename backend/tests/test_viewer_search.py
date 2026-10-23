"""Viewers must not be able to search (or count) text that is redacted for them."""

COLLECTOR = {"X-Collector-Key": "test-collector-key"}

ATTACK_EVENT = {
    "id": "33333333-3333-3333-3333-333333333333",
    "source": "simulated",
    "host": "SIM-WS01",
    "timestamp": "2026-10-21T05:00:00+00:00",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688,
    "user": "victim",
    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "command_line": r"powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\stage2.ps1",
    "parent_process": r"C:\Windows\System32\cmd.exe",
    "src_ip": None,
    "logon_type": None,
    "message": r"A new process has been created. Process Command Line: powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\stage2.ps1",
    "raw": '{"CommandLine": "powershell.exe -ExecutionPolicy Bypass", "Secret": "RawOnlyMarker"}',
}


def _headers(client, role):
    password = {"viewer": "TestViewerPass123!", "analyst": "TestAnalystPass123!"}[role]
    token = client.post("/api/auth/login", json={"username": f"test_{role}", "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _ingest(client):
    assert client.post("/api/events/ingest", json={"events": [ATTACK_EVENT]}, headers=COLLECTOR).status_code == 201


def _search(client, role, q):
    resp = client.get("/api/events", params={"q": q}, headers=_headers(client, role))
    assert resp.status_code == 200
    return resp.json()


def test_viewer_search_on_command_line_term_returns_nothing(client, seed_users):
    _ingest(client)
    assert _search(client, "viewer", "Bypass") == {"total": 0, "items": []}
    assert _search(client, "viewer", "stage2.ps1")["total"] == 0


def test_analyst_search_on_command_line_term_finds_event(client, seed_users):
    _ingest(client)
    body = _search(client, "analyst", "Bypass")
    assert body["total"] == 1
    assert "Bypass" in body["items"][0]["command_line"]


def test_viewer_search_on_message_only_term_returns_nothing(client, seed_users):
    _ingest(client)
    assert _search(client, "viewer", "new process has been created")["total"] == 0
    assert _search(client, "analyst", "new process has been created")["total"] == 1


def test_viewer_search_on_raw_only_term_returns_nothing(client, seed_users):
    _ingest(client)
    assert _search(client, "viewer", "RawOnlyMarker")["total"] == 0


def test_viewer_can_still_search_non_redacted_fields(client, seed_users):
    _ingest(client)
    for q in ("victim", "powershell.exe", "SIM-WS01", "Security", "4688"):
        assert _search(client, "viewer", q)["total"] == 1, q


def test_viewer_event_output_has_no_raw_and_redacted_content(client, seed_users):
    _ingest(client)
    item = _search(client, "viewer", "SIM-WS01")["items"][0]
    assert "raw" not in item
    assert "Bypass" not in item["command_line"]
    assert "Bypass" not in item["message"]
    assert "RawOnlyMarker" not in str(item)


def test_analyst_event_output_has_no_raw_either(client, seed_users):
    _ingest(client)
    item = _search(client, "analyst", "Bypass")["items"][0]
    assert "raw" not in item
