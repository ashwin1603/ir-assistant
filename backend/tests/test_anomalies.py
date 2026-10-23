import numpy as np

from app.analysis.iforest import IsolationForest

BASE_EVENT = {
    "source": "agent",
    "host": "HOST-A",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4688,
    "user": r"HOST-A\alice",
    "parent_process": r"C:\Windows\explorer.exe",
    "src_ip": None,
    "logon_type": None,
    "message": "A new process has been created.",
    "raw": "{}",
}


def _event(i: int, process: str, command_line: str, **extra) -> dict:
    return {
        **BASE_EVENT,
        "id": f"b{i:07d}-0000-0000-0000-000000000000",
        "timestamp": f"2026-10-21T09:{i % 60:02d}:00+00:00",
        "process": process,
        "command_line": command_line,
        **extra,
    }


def _normal_events(n: int = 40) -> list[dict]:
    return [_event(i, r"C:\Windows\System32\notepad.exe", f"notepad.exe file{i % 3}.txt") for i in range(n)]


ODD = _event(
    900,
    r"C:\Users\Public\x\y\z.exe",
    "z.exe --token 9f8a7c6b5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d|{}[]~",
)
SIM = _event(901, "C:/Windows/notepad.exe", "notepad.exe sim.txt", source="simulated")


def _ingest(client, events):
    resp = client.post("/api/events/ingest", json={"events": events}, headers={"X-Collector-Key": "test-collector-key"})
    assert resp.status_code == 201


def _viewer_headers(client):
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_anomalies_requires_auth(client):
    assert client.get("/api/anomalies").status_code == 401


def test_anomalies_viewer_can_read_and_odd_event_ranks_first(client, seed_users):
    _ingest(client, _normal_events() + [ODD, SIM])
    resp = client.get("/api/anomalies?limit=5", headers=_viewer_headers(client))
    assert resp.status_code == 200
    body = resp.json()
    assert body["trained_on"] == 41  # simulated event is scored but not trained on
    assert body["scored"] == 42
    assert len(body["items"]) == 5
    top = body["items"][0]
    assert top["event_id"] == ODD["id"]
    assert top["rank"] == 1 and top["is_anomaly"] is True
    assert top["label"] == "ML anomaly, unmapped"
    assert len(top["top_features"]) == 3


def test_anomalies_flags_rule_overlap(client, seed_users):
    # The encoded-PowerShell rule also fires on this event.
    encoded = _event(902, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell.exe -EncodedCommand SQBFAFgA")
    _ingest(client, _normal_events() + [encoded])
    items = client.get("/api/anomalies?limit=50", headers=_viewer_headers(client)).json()["items"]
    by_id = {item["event_id"]: item for item in items}
    assert by_id[encoded["id"]]["also_matched_rule"] is True
    assert by_id[_normal_events()[0]["id"]]["also_matched_rule"] is False


def test_anomalies_not_merged_into_incidents(client, seed_users):
    _ingest(client, _normal_events() + [ODD])
    headers = _viewer_headers(client)
    client.get("/api/anomalies", headers=headers)
    assert client.get("/api/incidents", headers=headers).json() == []


def test_anomalies_too_little_training_data(client, seed_users):
    _ingest(client, [ODD, SIM])
    body = client.get("/api/anomalies", headers=_viewer_headers(client)).json()
    assert body["trained_on"] == 1 and body["items"] == []


def test_anomalies_limit_validated(client, seed_users):
    assert client.get("/api/anomalies?limit=0", headers=_viewer_headers(client)).status_code == 422


def test_iforest_is_deterministic():
    X = np.random.default_rng(0).normal(size=(300, 8))
    first = IsolationForest().fit(X).score(X)
    second = IsolationForest().fit(X).score(X)
    assert np.array_equal(first, second)
    assert len(IsolationForest().fit(X).trees) == 100


def test_endpoint_is_deterministic(client, seed_users):
    _ingest(client, _normal_events() + [ODD])
    headers = _viewer_headers(client)
    assert client.get("/api/anomalies", headers=headers).json() == client.get("/api/anomalies", headers=headers).json()
