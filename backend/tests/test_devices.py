from datetime import datetime, timedelta, timezone

from app.models import Device, Event
from app.routes.devices import device_status

KEY = {"X-Collector-Key": "test-collector-key"}


def _token(client, user="test_viewer", password="TestViewerPass123!"):
    resp = client.post("/api/auth/login", json={"username": user, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _beat(client, headers=KEY, **body):
    payload = {"host": "PC1", "source": "agent", "events_sent": 5, **body}
    return client.post("/api/devices/heartbeat", json=payload, headers=headers)


# --- heartbeat auth ---

def test_heartbeat_without_key_is_401(client):
    assert _beat(client, headers={}).status_code == 401


def test_heartbeat_with_wrong_key_is_401(client):
    assert _beat(client, headers={"X-Collector-Key": "nope"}).status_code == 401


def test_heartbeat_rejects_user_jwt(client, seed_users):
    # Only the collector key may send heartbeats, not a logged-in user.
    headers = _token(client, "test_admin", "TestAdminPass123!")
    assert _beat(client, headers=headers).status_code == 401


def test_heartbeat_validates_input(client):
    assert _beat(client, source="simulated").status_code == 422
    assert _beat(client, events_sent=-1).status_code == 422


def test_heartbeat_upserts_and_accumulates(client, db_session):
    assert _beat(client, events_sent=5).status_code == 200
    assert _beat(client, events_sent=7).status_code == 200
    assert _beat(client, source="local-net", events_sent=1).status_code == 200
    rows = db_session.query(Device).order_by(Device.source).all()
    assert [(d.source, d.total_events) for d in rows] == [("agent", 12), ("local-net", 1)]


# --- devices list ---

def test_devices_requires_login(client):
    assert client.get("/api/devices").status_code == 401


def test_devices_rejects_collector_key_alone(client):
    assert client.get("/api/devices", headers=KEY).status_code == 401


def test_devices_readable_by_viewer(client, seed_users):
    _beat(client)
    resp = client.get("/api/devices", headers=_token(client))
    assert resp.status_code == 200
    [device] = resp.json()
    assert device["host"] == "PC1"
    assert device["status"] == "online"
    assert device["total_events"] == 5
    assert device["simulated"] is False


def test_devices_lists_simulated_hosts(client, seed_users, db_session):
    db_session.add(Event(id="sim-1", source="simulated", host="SIM-WS01", timestamp=datetime.now(timezone.utc),
                         channel="Security", provider="x", event_id=4688, raw="{}"))
    db_session.commit()
    [device] = client.get("/api/devices", headers=_token(client)).json()
    assert device["host"] == "SIM-WS01"
    assert device["simulated"] is True
    assert device["events_last_5m"] == 1


# --- status logic ---

def test_status_thresholds():
    now = datetime.now(timezone.utc)
    assert device_status(now - timedelta(seconds=10), now) == "online"
    assert device_status(now - timedelta(seconds=59), now) == "online"
    assert device_status(now - timedelta(seconds=60), now) == "stale"
    assert device_status(now - timedelta(seconds=299), now) == "stale"
    assert device_status(now - timedelta(minutes=5), now) == "offline"
    assert device_status(None, now) == "offline"


def test_status_handles_naive_sqlite_datetimes():
    now = datetime.now(timezone.utc)
    naive = (now - timedelta(seconds=5)).replace(tzinfo=None)
    assert device_status(naive, now) == "online"
