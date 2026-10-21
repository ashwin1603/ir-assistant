import json

import pytest

from app.config import settings
from app.models import AuditLog, Event

# A raw `Get-WinEvent | ConvertTo-Json` record: /Date()/ timestamps, Properties as {"Value": ...}.
ENCODED_PS_EVENT = {
    "Id": 4688,
    "RecordId": 5001,
    "TimeCreated": "/Date(1792558800000)/",
    "LogName": "Security",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "MachineName": "UPLOADHOST",
    "Message": "A new process has been created.",
    "Properties": [{"Value": v} for v in [
        "S-1-5-18", "victim", "DOMAIN", "0x3e7", "0x1234",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "%%1936", "0x999",
        "powershell.exe -NoP -EncodedCommand SQBFAFgA", "S-1-0-0", "-", "-", "0x0",
        "C:\\Windows\\explorer.exe",
    ]],
}


@pytest.fixture(autouse=True)
def tmp_upload_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "uploads"))
    return tmp_path / "uploads"


def _token(client, username="test_analyst", password="TestAnalystPass123!"):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _upload(client, headers, name, content: bytes):
    return client.post("/api/uploads", files={"file": (name, content, "application/octet-stream")}, headers=headers)


def test_upload_requires_auth(client):
    assert _upload(client, {}, "a.json", b"[]").status_code == 401


def test_viewer_cannot_upload(client, seed_users):
    headers = _token(client, "test_viewer", "TestViewerPass123!")
    assert _upload(client, headers, "a.json", json.dumps([ENCODED_PS_EVENT]).encode()).status_code == 403


def test_json_upload_normalizes_dedupes_and_detects(client, seed_users, db_session, tmp_upload_dir):
    headers = _token(client)
    body = json.dumps([ENCODED_PS_EVENT]).encode()

    first = _upload(client, headers, "export.json", body)
    assert first.status_code == 201
    assert first.json()["inserted"] == 1

    event = db_session.query(Event).one()
    assert event.source == "upload"
    assert event.host == "UPLOADHOST"
    assert "EncodedCommand" in event.command_line

    # The same file again is fully deduplicated.
    second = _upload(client, headers, "export.json", body)
    assert second.json() == {"filename": "export.json", "parsed": 1, "inserted": 0, "duplicates": 1}

    # Detection ran: the encoded PowerShell rule fired on the uploaded event.
    detections = client.get("/api/detections", headers=headers).json()
    assert any(event.id in d["matched_event_ids"] for d in detections)

    # Stored under a random name, and audited.
    stored = list(tmp_upload_dir.iterdir())
    assert stored and all(p.name != "export.json" and p.suffix == ".json" for p in stored)
    assert db_session.query(AuditLog).filter(AuditLog.action == "upload", AuditLog.success.is_(True)).count() == 2


def test_csv_upload(client, seed_users, db_session):
    csv_body = (
        "TimeCreated,Id,LogName,MachineName,user,Message\n"
        "2026-10-21T05:00:00Z,4720,Security,CSVHOST,eviladmin,A user account was created.\n"
    ).encode()
    resp = _upload(client, _token(client), "events.csv", csv_body)
    assert resp.status_code == 201
    assert db_session.query(Event).one().event_id == 4720


def test_rejects_bad_extension(client, seed_users, db_session):
    resp = _upload(client, _token(client), "payload.exe", b"MZ\x90\x00")
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.json()["detail"]
    assert db_session.query(AuditLog).filter(AuditLog.action == "upload", AuditLog.success.is_(False)).count() == 1


def test_rejects_mismatched_magic_bytes(client, seed_users):
    # An executable renamed to .evtx, and binary data renamed to .json.
    headers = _token(client)
    assert _upload(client, headers, "log.evtx", b"MZ\x90\x00" + b"\x00" * 100).status_code == 400
    assert _upload(client, headers, "log.json", b"\x89PNG\r\n\x1a\n\x00\x00").status_code == 400


def test_rejects_oversize(client, seed_users, monkeypatch):
    monkeypatch.setattr(settings, "upload_max_mb", 1)
    resp = _upload(client, _token(client), "big.json", b"[" + b" " * (1024 * 1024 + 10) + b"]")
    assert resp.status_code == 413


def test_traversal_filename_is_contained(client, seed_users, tmp_upload_dir, tmp_path):
    resp = _upload(client, _token(client), "../../../evil.json", json.dumps([ENCODED_PS_EVENT]).encode())
    assert resp.status_code == 201
    assert resp.json()["filename"] == "evil.json"
    assert not (tmp_path / "evil.json").exists()
    stored = list(tmp_upload_dir.iterdir())
    assert len(stored) == 1 and stored[0].name != "evil.json"


def test_traversal_windows_style_filename(client, seed_users, tmp_path):
    resp = _upload(client, _token(client), "..\\..\\evil.json", json.dumps([ENCODED_PS_EVENT]).encode())
    assert resp.status_code == 201
    assert not (tmp_path / "evil.json").exists()


@pytest.mark.parametrize(
    "name, content",
    [
        ("broken.json", b'[{"Id": 4688, "TimeCreated": '),  # truncated JSON
        ("wrong.json", b'[{"hello": "world"}]'),  # valid JSON, not events
        ("badid.json", b'[{"Id": "abc", "TimeCreated": "2026-10-21T05:00:00Z"}]'),
        ("bad.csv", b"TimeCreated,Id\n2026-10-21T05:00:00Z,not-a-number\n"),
        ("corrupt.evtx", b"ElfFile\x00" + b"\xff" * 4000),  # right magic, garbage body
        ("empty.json", b"[]"),
    ],
)
def test_rejects_malformed_files(client, seed_users, db_session, tmp_upload_dir, name, content):
    resp = _upload(client, _token(client), name, content)
    assert resp.status_code == 400
    assert db_session.query(Event).count() == 0
    assert not tmp_upload_dir.exists() or not any(tmp_upload_dir.iterdir())  # failed files are removed
