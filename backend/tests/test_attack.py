from tests.test_detection_routes import _auth_headers, _brute_force_events


def _ingest(client, events):
    client.post("/api/events/ingest", json={"events": events}, headers={"X-Collector-Key": "test-collector-key"})


def _cells(matrix):
    return {cell["technique_id"]: cell for column in matrix["tactics"] for cell in column["techniques"]}


def test_attack_endpoints_require_auth(client):
    assert client.get("/api/attack/matrix").status_code == 401
    assert client.get("/api/attack/techniques/T1110").status_code == 401


def test_matrix_shows_covered_but_unseen_techniques(client, seed_users):
    resp = client.get("/api/attack/matrix", headers=_auth_headers(client, seed_users))
    assert resp.status_code == 200
    cells = _cells(resp.json())
    assert "T1110" in cells and "T1070.001" in cells
    assert all(c["hit_count"] == 0 and c["max_risk_level"] is None for c in cells.values())


def test_matrix_colors_by_max_risk_and_filters_by_host(client, seed_users):
    _ingest(client, _brute_force_events())
    headers = _auth_headers(client, seed_users)

    matrix = client.get("/api/attack/matrix", headers=headers).json()
    brute = _cells(matrix)["T1110"]
    assert brute["hit_count"] == 1
    assert brute["max_risk_level"] is not None
    assert matrix["hosts"] == ["HOST-A"]
    credential_access = next(c for c in matrix["tactics"] if c["tactic"] == "Credential Access")
    assert any(t["technique_id"] == "T1110" for t in credential_access["techniques"])

    other_host = client.get("/api/attack/matrix?host=HOST-B", headers=headers).json()
    assert _cells(other_host)["T1110"]["hit_count"] == 0


def test_technique_detail(client, seed_users):
    _ingest(client, _brute_force_events())
    resp = client.get("/api/attack/techniques/t1110", headers=_auth_headers(client, seed_users))
    assert resp.status_code == 200
    body = resp.json()
    assert body["technique_id"] == "T1110"
    assert body["name"] == "Brute Force"
    assert body["tactic"] == "Credential Access"
    assert body["description"]
    assert [r["name"] for r in body["rules"]] == ["Brute force logon"]
    assert body["mitigations"]
    assert len(body["recent_detections"]) == 1
    assert body["recent_detections"][0]["incident_id"]


def test_technique_detail_unknown_returns_404(client, seed_users):
    headers = _auth_headers(client, seed_users)
    assert client.get("/api/attack/techniques/T9999", headers=headers).status_code == 404
