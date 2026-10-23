import json
import random
import string
from datetime import datetime, timedelta, timezone

import pytest

from app.collector.network import make_network_event
from app.detection.engine import run_detection
from app.detection.network_rules import (
    NETWORK_RULES,
    beacon_stats,
    detect_beaconing,
    detect_dns_tunnelling,
    detect_large_transfer,
    detect_port_scan,
    detect_uncommon_port,
    shannon_entropy,
    split_domain,
)
from app.models import AuditLog, Detection, Event
from tests.test_settings import COLLECTOR_HEADERS, _login

T0 = datetime(2026, 10, 23, 9, 0, 0)
MB = 1024 * 1024
RULES = {n.rule.name: n for n in NETWORK_RULES}


def _event(seconds, dst_ip="203.0.113.25", dst_port=443, process="evil.exe", bytes_out=None,
           src_ip="10.0.0.50", host="PC1", kind="network_connection", name=None):
    data = make_network_event(
        kind, host=host, timestamp=(T0 + timedelta(seconds=seconds)).isoformat(), source="simulated",
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, bytes_out=bytes_out, process=process,
        message=f"DNS query {name}" if name else "test", raw={"name": name} if name else {},
    )
    data["timestamp"] = T0 + timedelta(seconds=seconds)
    return Event(**data)


def _defaults(name):
    return RULES[name].defaults()


# ---------- 1. Port scan ----------

def test_port_scan_fires_at_15_ports_in_60s():
    events = [_event(i * 3, dst_ip="10.0.0.20", dst_port=1000 + i) for i in range(15)]
    hits = detect_port_scan(events, _defaults("Port scan"))
    assert len(hits) == 1 and len(hits[0][0]) == 15
    assert "15 distinct ports on 10.0.0.20" in hits[0][1]


def test_port_scan_not_fired_for_14_ports_or_slow_scan():
    assert detect_port_scan([_event(i, dst_port=1000 + i) for i in range(14)], _defaults("Port scan")) == []
    slow = [_event(i * 10, dst_port=1000 + i) for i in range(15)]  # 140s span
    assert detect_port_scan(slow, _defaults("Port scan")) == []


def test_port_scan_needs_one_destination():
    events = [_event(i, dst_ip=f"10.0.0.{i + 1}", dst_port=1000 + i) for i in range(20)]
    assert detect_port_scan(events, _defaults("Port scan")) == []


# ---------- 2. Beaconing ----------

def test_beaconing_regular_intervals_fire():
    offsets = [0, 1, -2, 2, -1, 0, 3, -1]  # a few seconds of jitter on a 60s beacon
    events = [_event(i * 60 + off) for i, off in enumerate(offsets)]
    hits = detect_beaconing(events, _defaults("Network beaconing"))
    assert len(hits) == 1
    assert "8 times about every 61 seconds" in hits[0][1]


def test_beaconing_irregular_or_too_few_do_not_fire():
    irregular = [_event(t) for t in (0, 10, 90, 100, 300, 320, 600, 610)]
    assert detect_beaconing(irregular, _defaults("Network beaconing")) == []
    assert detect_beaconing([_event(i * 60) for i in range(5)], _defaults("Network beaconing")) == []


def test_beaconing_tolerates_one_missed_checkin():
    times = [0, 60, 120, 180, 300, 360, 420]  # 240 missing
    median, jitter = beacon_stats([_event(t) for t in times])
    assert median == 60 and jitter == 0


def test_beaconing_groups_by_process_and_port():
    events = [_event(i * 60, process="a.exe" if i % 2 else "b.exe") for i in range(8)]
    assert detect_beaconing(events, _defaults("Network beaconing")) == []


# ---------- 3. Large outbound transfer ----------

def test_large_transfer_fires_on_external_sum():
    events = [_event(0, bytes_out=30 * MB), _event(60, bytes_out=25 * MB)]
    hits = detect_large_transfer(events, _defaults("Large outbound transfer"))
    assert len(hits) == 1 and "55.0 MB sent to external address 203.0.113.25" in hits[0][1]


def test_large_transfer_skips_private_and_small():
    assert detect_large_transfer([_event(0, dst_ip="192.168.1.10", bytes_out=500 * MB)], _defaults("Large outbound transfer")) == []
    assert detect_large_transfer([_event(0, dst_ip="127.0.0.1", bytes_out=500 * MB)], _defaults("Large outbound transfer")) == []
    assert detect_large_transfer([_event(0, bytes_out=49 * MB)], _defaults("Large outbound transfer")) == []


def test_large_transfer_threshold_is_editable():
    params = {**_defaults("Large outbound transfer"), "min_mb": 10}
    assert len(detect_large_transfer([_event(0, bytes_out=20 * MB)], params)) == 1


# ---------- 4. Uncommon port ----------

@pytest.mark.parametrize("port", [4444, 1337, 31337, 8888, 9001])
def test_uncommon_port_fires(port):
    hits = detect_uncommon_port([_event(0, dst_port=port, process="powershell.exe")], {})
    assert len(hits) == 1 and f"powershell.exe -> 203.0.113.25:{port}" in hits[0][1]


def test_uncommon_port_skips_private_and_normal_ports():
    assert detect_uncommon_port([_event(0, dst_ip="10.0.0.9", dst_port=4444)], {}) == []
    assert detect_uncommon_port([_event(0, dst_ip="::1", dst_port=4444)], {}) == []
    assert detect_uncommon_port([_event(0, dst_port=443)], {}) == []


# ---------- 5. DNS tunnelling ----------

def _dns(seconds, name, host="PC1"):
    return _event(seconds, dst_ip=None, dst_port=None, process=None, kind="dns_query", name=name, host=host)


def _random_label(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def test_dns_tunnelling_fires_on_long_unique_subdomains():
    events = [_dns(i * 5, f"{_random_label(40)}.data.exfil-example.net") for i in range(12)]
    hits = detect_dns_tunnelling(events, _defaults("Possible DNS tunnelling"))
    assert len(hits) == 1 and "12 unique subdomains of exfil-example.net" in hits[0][1]


def test_dns_tunnelling_ignores_normal_lookups():
    normal = [_dns(i, f"{name}.microsoft.com") for i, name in enumerate(
        ["www", "login", "update", "settings-win.data", "graph", "outlook", "teams", "store", "docs", "learn", "azure"])]
    assert detect_dns_tunnelling(normal, _defaults("Possible DNS tunnelling")) == []
    few = [_dns(i, f"{_random_label(40)}.exfil-example.net") for i in range(9)]
    assert detect_dns_tunnelling(few, _defaults("Possible DNS tunnelling")) == []
    slow = [_dns(i * 30, f"{_random_label(40)}.exfil-example.net") for i in range(12)]  # spread over 5.5 min
    assert detect_dns_tunnelling(slow, _defaults("Possible DNS tunnelling")) == []


def test_domain_helpers():
    assert split_domain("abc.def.example.com") == ("abc.def", "example.com")
    assert split_domain("example.com") == ("", "example.com")
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2


# ---------- pipeline, Settings, AI facts, Network page ----------

def _seed(db_session):
    events = [_event(i * 2, dst_ip="10.0.0.20", dst_port=2000 + i, process="nmap.exe") for i in range(20)]
    events += [_event(600, dst_ip="198.51.100.66", bytes_out=120 * MB, process="rclone.exe")]
    events += [_event(700, dst_port=4444, process="powershell.exe")]
    db_session.add_all(events)
    db_session.commit()


def test_network_detections_go_through_pipeline(db_session):
    _seed(db_session)
    run_detection(db_session)
    detections = {d.rule_name: d for d in db_session.query(Detection).all()}
    assert {"Port scan", "Large outbound transfer", "Connection to uncommon port"} <= set(detections)
    scan = detections["Port scan"]
    assert json.loads(scan.technique_ids) == ["T1046"] and json.loads(scan.tactics) == ["Discovery"]
    assert scan.incident_id and scan.risk_score > 0 and scan.summary
    assert json.loads(detections["Large outbound transfer"].tactics) == ["Exfiltration"]


def test_settings_lists_network_rules_and_edits_thresholds(client, seed_users, db_session):
    admin = _login(client, "test_admin", "TestAdminPass123!")
    rules = {r["name"]: r for r in client.get("/api/settings/rules", headers=admin).json()}
    exfil = rules["Large outbound transfer"]
    assert exfil["source"] == "network" and exfil["description"]
    assert {p["key"]: p["value"] for p in exfil["params"]} == {"min_mb": 50, "window_minutes": 60}

    db_session.add(_event(0, bytes_out=20 * MB))
    db_session.commit()
    run_detection(db_session)
    assert db_session.query(Detection).filter_by(rule_name="Large outbound transfer").count() == 0

    resp = client.patch(f"/api/settings/rules/{exfil['id']}", headers=admin, json={"params": {"min_mb": 10}})
    assert resp.status_code == 200
    assert next(p for p in resp.json()["params"] if p["key"] == "min_mb")["value"] == 10
    run_detection(db_session)
    assert db_session.query(Detection).filter_by(rule_name="Large outbound transfer").count() == 1
    assert any(a.action == "rule_update" and "min_mb=10" in a.detail for a in db_session.query(AuditLog).all())

    resp = client.patch(f"/api/settings/rules/{exfil['id']}", headers=admin, json={"enabled": False})
    assert resp.json()["enabled"] is False
    run_detection(db_session)
    assert db_session.query(Detection).filter_by(rule_name="Large outbound transfer").count() == 0


def test_network_threshold_validation(client, seed_users):
    admin = _login(client, "test_admin", "TestAdminPass123!")
    rules = {r["name"]: r for r in client.get("/api/settings/rules", headers=admin).json()}
    scan_id, dns_id = rules["Port scan"]["id"], rules["Possible DNS tunnelling"]["id"]
    assert client.patch(f"/api/settings/rules/{scan_id}", headers=admin, json={"params": {"min_ports": 0}}).status_code == 400
    assert client.patch(f"/api/settings/rules/{scan_id}", headers=admin, json={"params": {"min_ports": 2.5}}).status_code == 400
    assert client.patch(f"/api/settings/rules/{scan_id}", headers=admin, json={"params": {"bogus": 1}}).status_code == 400
    assert client.patch(f"/api/settings/rules/{scan_id}", headers=admin, json={"min_count": 3}).status_code == 400
    assert client.patch(f"/api/settings/rules/{dns_id}", headers=admin, json={"params": {"min_entropy": 4.2}}).status_code == 200
    brute = next(r for r in rules.values() if r["kind"] == "cluster")
    assert client.patch(f"/api/settings/rules/{brute['id']}", headers=admin, json={"params": {"min_mb": 1}}).status_code == 400


def test_network_page_all_roles_and_host_filter(client, seed_users, db_session):
    _seed(db_session)
    db_session.add(_event(0, dst_ip="142.250.183.14", process="chrome.exe", bytes_out=1000, host="PC2"))
    db_session.commit()
    viewer = _login(client, "test_viewer", "TestViewerPass123!")
    data = client.get("/api/network/summary", headers=viewer).json()
    assert data["hosts"] == ["PC1", "PC2"]
    assert data["top_destinations"][0] == {"dst_ip": "10.0.0.20", "count": 20}
    assert data["top_processes"][0] == {"process": "nmap.exe", "count": 20}
    assert data["bytes_by_destination"][0] == {"dst_ip": "198.51.100.66", "bytes_out": 120 * MB}
    assert {d["rule_name"] for d in data["detections"]} >= {"Port scan", "Connection to uncommon port"}

    pc2 = client.get("/api/network/summary", params={"host": "PC2"}, headers=viewer).json()
    assert [d["dst_ip"] for d in pc2["top_destinations"]] == ["142.250.183.14"] and pc2["detections"] == []
    assert client.get("/api/network/summary").status_code == 401


def test_network_facts_in_report_and_ai(client, seed_users, db_session):
    _seed(db_session)
    analyst = _login(client, "test_analyst", "TestAnalystPass123!")
    incident = client.get("/api/incidents", headers=analyst).json()[0]
    report = client.get(f"/api/incidents/{incident['id']}/report", headers=analyst).json()
    summaries = [e["summary"] for e in report["incident"]["timeline"] if e["summary"]]
    assert any("120.0 MB sent to external address 198.51.100.66" in s for s in summaries)
    assert "A large amount of data was sent from the machine to an outside address." in report["executive"]["what_happened"]

    analysis = client.post(f"/api/incidents/{incident['id']}/analyze", headers=analyst).json()
    assert any("probed 20 distinct ports" in f["claim"] for f in analysis["findings"])


def test_ingested_network_events_detected(client, seed_users):
    events = [make_network_event("network_connection", host="PC9", timestamp=(T0 + timedelta(seconds=i * 60)).isoformat(),
                                 source="agent", dst_ip="203.0.113.25", dst_port=443, process="rundll32.exe")
              for i in range(7)]
    assert client.post("/api/events/ingest", json={"events": events}, headers=COLLECTOR_HEADERS).status_code == 201
    analyst = _login(client, "test_analyst", "TestAnalystPass123!")
    names = [d["rule_name"] for d in client.get("/api/detections", headers=analyst).json()]
    assert "Network beaconing" in names
