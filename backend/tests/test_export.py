"""CSV export of the current view: role-checked, redacted for viewers, capped, audited, injection-safe."""

import csv
import io

import app.routes.events as events_routes
from app.auth.security import hash_password
from app.export import MAX_EXPORT_ROWS, safe_cell
from app.models import AuditLog, User

COLLECTOR = {"X-Collector-Key": "test-collector-key"}
PASSWORDS = {"viewer": "TestViewerPass123!", "analyst": "TestAnalystPass123!", "admin": "TestAdminPass123!"}

ATTACK_EVENT = {
    "id": "44444444-4444-4444-4444-444444444444",
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
    "raw": "{}",
}


def _headers(client, role):
    token = client.post("/api/auth/login", json={"username": f"test_{role}", "password": PASSWORDS[role]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _ingest(client, *events):
    assert client.post("/api/events/ingest", json={"events": list(events)}, headers=COLLECTOR).status_code == 201


def _rows(resp):
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    return list(csv.reader(io.StringIO(resp.text)))


# ---------- 401 / 403 ----------


def test_export_requires_a_token(client, seed_users):
    assert client.get("/api/events/export").status_code == 401
    assert client.get("/api/detections/export").status_code == 401


def test_export_rejects_a_role_without_read(client, db_session):
    # A role outside the permission table gets 403, like every other "read" route.
    db_session.add(User(username="test_guest", password_hash=hash_password("TestGuestPass123!"), role="guest"))
    db_session.commit()
    token = client.post("/api/auth/login", json={"username": "test_guest", "password": "TestGuestPass123!"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/events/export", headers=headers).status_code == 403
    assert client.get("/api/detections/export", headers=headers).status_code == 403


# ---------- redaction ----------


def test_viewer_export_has_command_lines_redacted(client, seed_users):
    _ingest(client, ATTACK_EVENT)
    text = client.get("/api/events/export", headers=_headers(client, "viewer")).text
    assert "Bypass" not in text and "stage2.ps1" not in text
    assert "[redacted for viewer role]" in text
    rows = _rows(client.get("/api/events/export", headers=_headers(client, "viewer")))
    assert len(rows) == 2  # header + the one event


def test_analyst_export_has_full_command_lines(client, seed_users):
    _ingest(client, ATTACK_EVENT)
    text = client.get("/api/events/export", headers=_headers(client, "analyst")).text
    assert "Bypass" in text


def test_viewer_export_search_cannot_match_redacted_text(client, seed_users):
    _ingest(client, ATTACK_EVENT)
    rows = _rows(client.get("/api/events/export", params={"q": "Bypass"}, headers=_headers(client, "viewer")))
    assert len(rows) == 1  # header only: no oracle for redacted content


# ---------- cap, columns, CSV injection ----------


def test_export_is_capped(client, seed_users, monkeypatch):
    assert MAX_EXPORT_ROWS == 5000
    monkeypatch.setattr(events_routes, "MAX_EXPORT_ROWS", 3)
    _ingest(client, *[{**ATTACK_EVENT, "id": f"55555555-0000-0000-0000-00000000000{i}"} for i in range(5)])
    resp = client.get("/api/events/export", headers=_headers(client, "analyst"))
    assert len(_rows(resp)) == 1 + 3
    assert resp.headers["X-Export-Truncated"] == "true"
    assert resp.headers["X-Export-Rows"] == "3"


def test_export_uses_only_requested_columns(client, seed_users):
    _ingest(client, ATTACK_EVENT)
    rows = _rows(client.get("/api/events/export", params={"columns": "timestamp,host,event_id"}, headers=_headers(client, "analyst")))
    assert rows[0] == ["timestamp", "host", "event_id"]
    assert rows[1][1:] == ["SIM-WS01", "4688"]


def test_export_rejects_unknown_columns(client, seed_users):
    resp = client.get("/api/events/export", params={"columns": "host,raw"}, headers=_headers(client, "analyst"))
    assert resp.status_code == 422


def test_cells_that_look_like_formulas_are_neutralised(client, seed_users):
    _ingest(client, {**ATTACK_EVENT, "user": "=HYPERLINK(\"http://evil\")", "command_line": None, "message": "@SUM(A1)"})
    rows = _rows(client.get("/api/events/export", params={"columns": "user,message"}, headers=_headers(client, "analyst")))
    assert rows[1] == ["'=HYPERLINK(\"http://evil\")", "'@SUM(A1)"]
    assert [safe_cell(v) for v in ("+1", "-2", "\tx", "ok", None)] == ["'+1", "'-2", "'\tx", "ok", ""]


# ---------- audit ----------


def test_export_is_audit_logged_without_content(client, seed_users, db_session):
    _ingest(client, ATTACK_EVENT)
    client.get("/api/events/export", params={"q": "Bypass"}, headers=_headers(client, "analyst"))
    client.get("/api/detections/export", headers=_headers(client, "viewer"))
    entries = db_session.query(AuditLog).filter(AuditLog.action == "export").all()
    assert {(e.actor, e.detail.split(":")[0]) for e in entries} == {("test_analyst", "events"), ("test_viewer", "detections")}
    analyst = next(e for e in entries if e.actor == "test_analyst")
    assert analyst.detail == "events: 1 rows"
    assert "Bypass" not in " ".join(e.detail for e in entries)


def test_detection_export_lists_detections(client, seed_users):
    _ingest(client, {**ATTACK_EVENT, "event_id": 1102, "channel": "Security", "command_line": None})
    rows = _rows(client.get("/api/detections/export", params={"columns": "rule_name,host,risk_level"}, headers=_headers(client, "viewer")))
    assert rows[0] == ["rule_name", "host", "risk_level"]
    assert any(r[1] == "SIM-WS01" for r in rows[1:])
