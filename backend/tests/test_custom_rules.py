import json
from datetime import datetime, timezone

import pytest
import yaml

from app.detection import rules as rules_module
from app.models import AuditLog, Detection, Event
from tests.test_settings import _login

URL = "/api/settings/rules/custom"
BUILTIN_ID = "adae165f-ba79-4519-9ecf-5e18cf7ba598"  # Encoded PowerShell command

VALID = {
    "title": "Certutil download",
    "description": "certutil used to fetch a file",
    "level": "high",
    "confidence": 0.7,
    "technique_ids": ["T1105"],
    "event_id": 4688,
    "groups": [
        {"conditions": [
            {"field": "process", "op": "endswith", "value": "\\certutil.exe"},
            {"field": "command_line", "op": "regex", "value": r"-urlcache\s+-f"},
        ]},
    ],
    "threshold": None,
}


@pytest.fixture(autouse=True)
def isolated_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_module, "CUSTOM_DIR", tmp_path)
    saved = list(rules_module.RULES)
    yield tmp_path
    rules_module.RULES[:] = saved


@pytest.fixture()
def admin(client, seed_users):
    return _login(client, "test_admin", "TestAdminPass123!")


def _event(db, n, command_line, process="C:\\Windows\\System32\\certutil.exe"):
    db.add(Event(
        id=f"evt-{n}", source="local", host="PC1", timestamp=datetime(2026, 10, 1, 12, n, tzinfo=timezone.utc),
        channel="Security", provider="p", event_id=4688, user="bob", process=process,
        command_line=command_line, message="m", raw=json.dumps({}),
    ))
    db.commit()


def test_valid_rule_saved_disabled_editable_and_deletable(client, admin, db_session, isolated_rules):
    resp = client.post(URL, headers=admin, json=VALID)
    assert resp.status_code == 201
    body = resp.json()
    assert body["enabled"] is False and body["source"] == "custom" and body["severity"] == 7
    saved = yaml.safe_load((isolated_rules / f"{body['id']}.yml").read_text())
    assert saved["detection"]["match"][0]["command_line|re2"] == r"-urlcache\s+-f"

    # Reopen, edit, then delete.
    form = client.get(f"/api/settings/rules/{body['id']}/form", headers=admin).json()
    assert form["title"] == "Certutil download"
    edited = client.put(f"{URL}/{body['id']}", headers=admin, json={**VALID, "title": "Certutil v2"})
    assert edited.status_code == 200 and edited.json()["name"] == "Certutil v2"
    assert client.delete(f"{URL}/{body['id']}", headers=admin).status_code == 204
    assert not (isolated_rules / f"{body['id']}.yml").exists()
    assert all(r.id != body["id"] for r in rules_module.RULES)

    actions = [a.action for a in db_session.query(AuditLog).all()]
    assert {"custom_rule_create", "custom_rule_edit", "custom_rule_delete"} <= set(actions)


def test_regex_re2_cannot_compile_is_rejected(client, admin, db_session):
    bad = {**VALID, "groups": [{"conditions": [{"field": "command_line", "op": "regex", "value": r"(?=lookahead)x"}]}]}
    resp = client.post(URL, headers=admin, json=bad)
    assert resp.status_code == 400 and "RE2" in resp.json()["detail"]
    audit = db_session.query(AuditLog).filter(AuditLog.action == "custom_rule_create").one()
    assert not audit.success


def test_too_many_conditions_rejected(client, admin):
    conditions = [{"field": "command_line", "op": "contains", "value": f"x{i}"} for i in range(11)]
    resp = client.post(URL, headers=admin, json={**VALID, "groups": [{"conditions": conditions}]})
    assert resp.status_code == 400 and "limit is 10" in resp.json()["detail"]


@pytest.mark.parametrize("technique", ["T105", "t1105", "T1105.1", "T1105; DROP"])
def test_bad_technique_id_rejected(client, admin, technique):
    assert client.post(URL, headers=admin, json={**VALID, "technique_ids": [technique]}).status_code == 422


def test_non_admin_forbidden(client, seed_users):
    analyst = _login(client, "test_analyst", "TestAnalystPass123!")
    assert client.post(URL, headers=analyst, json=VALID).status_code == 403
    assert client.post(f"{URL}/test", headers=analyst, json=VALID).status_code == 403
    assert client.delete(f"{URL}/{BUILTIN_ID}", headers=analyst).status_code == 403


def test_dry_run_matches_masks_and_creates_nothing(client, admin, db_session, isolated_rules):
    _event(db_session, 1, "certutil -urlcache -f http://x/a.exe a.exe token=abcdef123 " + "A" * 200)
    _event(db_session, 2, "certutil -urlcache -f http://x/b.exe b.exe")
    _event(db_session, 3, "notepad.exe", process="C:\\Windows\\notepad.exe")

    resp = client.post(f"{URL}/test", headers=admin, json=VALID)
    assert resp.status_code == 200
    body = resp.json()
    assert body["match_count"] == 2 and body["cluster_count"] is None
    lines = [s["command_line"] for s in body["samples"]]
    assert all(len(line) <= 120 for line in lines)
    assert not any("abcdef123" in line for line in lines) and any("[REDACTED]" in line for line in lines)

    assert db_session.query(Detection).count() == 0
    assert list(isolated_rules.iterdir()) == []
    assert all(r.name != "Certutil download" for r in rules_module.RULES)
    assert db_session.query(AuditLog).filter(AuditLog.action == "custom_rule_test").one().success


def test_builtin_rule_read_only_but_cloneable(client, admin):
    assert client.put(f"{URL}/{BUILTIN_ID}", headers=admin, json=VALID).status_code == 400
    assert client.delete(f"{URL}/{BUILTIN_ID}", headers=admin).status_code == 400
    assert any(r.id == BUILTIN_ID for r in rules_module.RULES)

    clone = client.get(f"/api/settings/rules/{BUILTIN_ID}/form", headers=admin)
    assert clone.status_code == 200
    form = clone.json()
    assert form["event_id"] == 4688 and form["groups"][0]["conditions"][0]["op"] == "regex"
    assert client.post(URL, headers=admin, json=form).status_code == 201
