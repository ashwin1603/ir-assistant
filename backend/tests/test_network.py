from pathlib import Path

import pytest

from app.collector.network import (
    NetworkDeduper,
    connection_to_event,
    dns_to_event,
    is_local_address,
)
from app.config import settings
from app.models import Event
from app.schemas import EventIn

SAMPLE_FLOWS = Path(__file__).resolve().parents[2] / "docs" / "sample_flows.csv"
FLOW_HEADER = "ts,src_ip,dst_ip,dst_port,proto,bytes_out,process\n"


@pytest.fixture(autouse=True)
def tmp_upload_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "uploads"))


def _token(client):
    resp = client.post("/api/auth/login", json={"username": "test_analyst", "password": "TestAnalystPass123!"})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _upload(client, headers, content: bytes, name="flows.csv"):
    return client.post("/api/uploads", files={"file": (name, content, "text/csv")}, headers=headers)


# --- normalization ---

def test_connection_normalizes_to_network_event():
    conn = {"LocalAddress": "10.0.0.5", "RemoteAddress": "203.0.113.25", "RemotePort": 443,
            "State": "Established", "OwningProcess": 1234, "ProcessName": "chrome"}
    event = connection_to_event(conn, host="PC1", timestamp="2026-10-23T09:00:00+00:00")
    EventIn(**event)  # passes API validation
    assert event["channel"] == "Network"
    assert event["provider"] == "network_connection"
    assert event["event_id"] == 3
    assert event["source"] == "local-net"
    assert (event["src_ip"], event["dst_ip"], event["dst_port"]) == ("10.0.0.5", "203.0.113.25", 443)
    assert event["process"] == "chrome"


def test_dns_normalizes_to_dns_query():
    event = dns_to_event({"Entry": "example.com", "Data": "93.184.216.34"}, host="PC1",
                         timestamp="2026-10-23T09:00:00+00:00")
    EventIn(**event)
    assert event["provider"] == "dns_query"
    assert event["event_id"] == 22
    assert event["dst_ip"] == "93.184.216.34"
    assert "example.com" in event["message"]


@pytest.mark.parametrize("ip,local", [
    ("127.0.0.1", True), ("::1", True), ("169.254.1.1", True), ("fe80::1", True),
    ("0.0.0.0", True), ("garbage", True), ("8.8.8.8", False), ("10.0.0.20", False),
])
def test_is_local_address(ip, local):
    assert is_local_address(ip) is local


# --- collector dedupe ---

def test_deduper_reports_each_connection_once_and_skips_loopback():
    d = NetworkDeduper()
    conns = [
        {"OwningProcess": 1, "RemoteAddress": "8.8.8.8", "RemotePort": 443},
        {"OwningProcess": 1, "RemoteAddress": "8.8.8.8", "RemotePort": 443},  # same poll duplicate
        {"OwningProcess": 2, "RemoteAddress": "8.8.8.8", "RemotePort": 443},  # different pid
        {"OwningProcess": 1, "RemoteAddress": "127.0.0.1", "RemotePort": 5000},
    ]
    assert len(d.new_connections(conns)) == 2
    assert d.new_connections(conns) == []  # next poll: nothing new


def test_deduper_dns_case_insensitive():
    d = NetworkDeduper()
    assert len(d.new_dns([{"Entry": "Example.com"}, {"Entry": "example.COM"}, {"Entry": ""}])) == 1
    assert d.new_dns([{"Entry": "example.com"}]) == []


# --- flow CSV upload ---

def test_flow_csv_upload_and_dedupe(client, seed_users, db_session):
    headers = _token(client)
    body = SAMPLE_FLOWS.read_bytes()
    rows = body.decode().strip().count("\n")

    first = _upload(client, headers, body)
    assert first.status_code == 201
    # Rows sharing a timestamp (port scan) must not be merged by dedupe.
    assert first.json()["inserted"] == rows

    exfil = db_session.query(Event).filter(Event.dst_ip == "198.51.100.66").one()
    assert exfil.channel == "Network" and exfil.source == "upload"
    assert exfil.bytes_out == 125829120 and exfil.dst_port == 443 and exfil.protocol == "tcp"

    second = _upload(client, headers, body)
    assert second.json()["inserted"] == 0
    assert second.json()["duplicates"] == rows


@pytest.mark.parametrize("row", [
    "2026-10-23T09:00:00Z,10.0.0.5,,443,TCP,1,x.exe",          # missing dst_ip
    "2026-10-23T09:00:00Z,10.0.0.5,8.8.8.8,notaport,TCP,1,x",   # bad port
    "2026-10-23T09:00:00Z,10.0.0.5,8.8.8.8,70000,TCP,1,x",      # port out of range
    "2026-10-23T09:00:00Z,10.0.0.5,8.8.8.8,443,TCP,-5,x",       # negative bytes
])
def test_flow_csv_rejects_invalid_rows(client, seed_users, db_session, row):
    resp = _upload(client, _token(client), (FLOW_HEADER + row + "\n").encode())
    assert resp.status_code == 400
    assert db_session.query(Event).count() == 0


def test_ingest_rejects_unknown_source(client):
    event = connection_to_event({"RemoteAddress": "8.8.8.8", "RemotePort": 443}, host="PC1",
                                timestamp="2026-10-23T09:00:00+00:00", source="evil")
    resp = client.post("/api/events/ingest", json={"events": [event]}, headers={"X-Collector-Key": "test-collector-key"})
    assert resp.status_code == 422
