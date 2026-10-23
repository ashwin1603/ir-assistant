from tests.test_incident_status import BASE_EVENT, COLLECTOR, _analyst, _login


def _seed(client):
    events = [
        {**BASE_EVENT, "id": f"c000000{i}-0000-0000-0000-000000000000", "timestamp": f"2026-10-21T05:00:0{i}+00:00"}
        for i in range(5)
    ]
    events.append(
        {
            **BASE_EVENT,
            "id": "c0000009-0000-0000-0000-000000000000",
            "timestamp": "2026-10-21T05:01:00+00:00",
            "event_id": 4720,
            "message": "A user account was created.",
        }
    )
    client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR)


def _incident_id(client, headers):
    return client.get("/api/incidents", headers=headers).json()[0]["id"]


def test_graph_nodes_and_edges(client, seed_users):
    _seed(client)
    headers = _analyst(client)
    resp = client.get(f"/api/incidents/{_incident_id(client, headers)}/graph", headers=headers)
    assert resp.status_code == 200
    graph = resp.json()

    by_type = {}
    for node in graph["nodes"]:
        by_type.setdefault(node["type"], []).append(node)
    assert by_type["host"][0]["label"] == "HOST-A"
    assert by_type["user"][0]["label"] == "fakeuser"
    detections = by_type["detection"]
    assert len(detections) == 2
    assert detections[0]["technique"] == "T1110"
    assert detections[0]["first_seen"] <= detections[1]["first_seen"]
    assert all(d["risk_level"] and d["tactic"] for d in detections)

    edges = [(e["source"], e["target"], e["kind"]) for e in graph["edges"]]
    assert ("user:fakeuser", "host:HOST-A", "account") in edges
    assert ("host:HOST-A", detections[0]["id"], "start") in edges
    assert (detections[0]["id"], detections[1]["id"], "sequence") in edges


def test_graph_viewer_allowed_and_auth_required(client, seed_users):
    _seed(client)
    headers = _login(client, "test_viewer", "TestViewerPass123!")
    incident_id = _incident_id(client, headers)
    assert client.get(f"/api/incidents/{incident_id}/graph", headers=headers).status_code == 200
    assert client.get(f"/api/incidents/{incident_id}/graph").status_code == 401


def test_graph_unknown_incident_404(client, seed_users):
    resp = client.get("/api/incidents/does-not-exist/graph", headers=_analyst(client))
    assert resp.status_code == 404
