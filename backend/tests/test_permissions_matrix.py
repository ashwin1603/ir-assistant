"""Least-privilege matrix: every API route is in ROUTE_PERMISSIONS, and every role gets
exactly 401 / 403 / access as the PERMISSIONS table says."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.auth.permissions import (
    COLLECTOR,
    MFA_ENROLMENT,
    PERMISSIONS,
    PUBLIC,
    ROUTE_PERMISSIONS,
    authorize,
)
from app.db import get_db
from app.main import app
from app.models import AuditLog, Event

PASSWORDS = {"admin": "TestAdminPass123!", "analyst": "TestAnalystPass123!", "viewer": "TestViewerPass123!"}

VIEWER_ACTIONS = {"account", "read", "chat"}
ANALYST_ACTIONS = VIEWER_ACTIONS | {
    "view_command_lines", "upload", "run_ai", "update_incident", "decide_actions", "download_artifacts",
}
ADMIN_ACTIONS = ANALYST_ACTIONS | {
    "manage_users", "manage_rules", "import_sigma", "manage_threat_intel", "manage_settings", "read_audit",
}


def _api_routes() -> set[tuple[str, str]]:
    return {(method.upper(), path) for path, ops in app.openapi()["paths"].items() for method in ops}


def _login(client, role):
    resp = client.post("/api/auth/login", json={"username": f"test_{role}", "password": PASSWORDS[role]})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture()
def tokens(client, seed_users):
    out = {role: _login(client, role) for role in PASSWORDS}
    # Step-up-protected admin routes would otherwise answer 403 "step-up required".
    assert client.post("/api/auth/step-up", json={"password": PASSWORDS["admin"]}, headers=out["admin"]).status_code == 204
    return out


@pytest.fixture()
def incident_id(client, tokens, db_session):
    db_session.add(Event(
        id="perm-1102", source="local", host="PC1", timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
        channel="Security", provider="Microsoft-Windows-Eventlog", event_id=1102, user="bob",
        message="The audit log was cleared.", raw=json.dumps({}),
    ))
    db_session.commit()
    return client.get("/api/incidents", headers=tokens["admin"]).json()[0]["id"]


# ---------- the tables themselves ----------


def test_every_route_is_in_the_permission_table():
    missing = _api_routes() - set(ROUTE_PERMISSIONS)
    assert not missing, f"routes missing from ROUTE_PERMISSIONS: {sorted(missing)}"


def test_permission_table_has_no_stale_routes():
    stale = set(ROUTE_PERMISSIONS) - _api_routes()
    assert not stale, f"ROUTE_PERMISSIONS entries with no route: {sorted(stale)}"


def test_every_route_action_is_defined():
    special = {PUBLIC, COLLECTOR, MFA_ENROLMENT}
    assert {a for a in ROUTE_PERMISSIONS.values() if a not in special} <= set(PERMISSIONS)


@pytest.mark.parametrize("role,expected", [("viewer", VIEWER_ACTIONS), ("analyst", ANALYST_ACTIONS), ("admin", ADMIN_ACTIONS)])
def test_role_actions_match_the_spec(role, expected):
    assert {a for a, roles in PERMISSIONS.items() if role in roles} == expected


def test_only_health_login_and_mfa_verify_are_public():
    public = {route for route, action in ROUTE_PERMISSIONS.items() if action == PUBLIC}
    assert public == {("GET", "/api/health"), ("POST", "/api/auth/login"), ("POST", "/api/auth/mfa/verify")}


def test_unlisted_route_is_denied_by_default(client, tokens):
    # A route someone forgot to add to the table: authenticated callers still get 403.
    mini = FastAPI(dependencies=[Depends(authorize)])
    mini.dependency_overrides[get_db] = app.dependency_overrides[get_db]

    @mini.get("/api/not-in-table")
    def _unlisted():
        return {"leak": True}

    with TestClient(mini) as c:
        assert c.get("/api/not-in-table", headers=tokens["admin"]).status_code == 403
        assert c.get("/api/not-in-table").status_code == 401


# ---------- the matrix ----------


def _url(path: str, incident_id: str, rule_id: str) -> str:
    values = {"incident_id": incident_id, "kind": "firewall", "technique_id": "T1070.001", "rule_id": rule_id,
              "action_id": "nope", "user_id": "nope", "indicator_id": "nope"}
    for key, value in values.items():
        path = path.replace("{" + key + "}", value)
    return path


def _call(client, method, url, headers):
    if method in ("POST", "PUT", "PATCH"):
        return client.request(method, url, headers=headers, json={})
    return client.request(method, url, headers=headers)


def test_matrix_no_token_gives_401(client, seed_users):
    for (method, path), action in ROUTE_PERMISSIONS.items():
        if action == PUBLIC:
            continue
        resp = _call(client, method, _url(path, "x", "x"), {})
        assert resp.status_code == 401, f"{method} {path}: {resp.status_code}"


def test_matrix_per_role(client, tokens, incident_id):
    rule_id = client.get("/api/settings/rules", headers=tokens["admin"]).json()[0]["id"]
    problems = []
    for (method, path), action in sorted(ROUTE_PERMISSIONS.items()):
        if action == PUBLIC:
            continue
        url = _url(path, incident_id, rule_id)
        for role, headers in tokens.items():
            status = _call(client, method, url, headers).status_code
            if status >= 500:
                problems.append(f"{role} {method} {path}: {status}")
            elif action == COLLECTOR:
                if status != 401:  # a user token is never a collector key
                    problems.append(f"{role} {method} {path}: expected 401, got {status}")
            elif action == MFA_ENROLMENT or role in PERMISSIONS[action]:
                if status in (401, 403):
                    problems.append(f"{role} {method} {path}: expected access, got {status}")
                elif method == "GET" and status != 200:
                    problems.append(f"{role} {method} {path}: expected 200, got {status}")
            elif status != 403:
                problems.append(f"{role} {method} {path}: expected 403, got {status}")
    assert not problems, "\n".join(problems)


def test_collector_routes_accept_only_the_collector_key(client, seed_users):
    key = {"X-Collector-Key": "test-collector-key"}
    beat = {"host": "PC1", "source": "agent", "events_sent": 0}
    assert client.post("/api/devices/heartbeat", json=beat, headers=key).status_code == 200
    assert client.delete("/api/events/simulated", headers=key).status_code == 200  # test DB: deletes nothing


# ---------- denied attempts are audited ----------


def test_403_is_audit_logged_with_actor_and_route_but_no_body(client, tokens, db_session):
    secret = "VerySecretPassword123!"
    resp = client.post("/api/settings/users", headers=tokens["viewer"],
                       json={"username": "mallory", "password": secret, "role": "admin"})
    assert resp.status_code == 403
    assert client.get("/api/audit", headers=tokens["analyst"]).status_code == 403

    denied = db_session.query(AuditLog).filter(AuditLog.action == "access_denied").all()
    assert {(d.actor, d.detail) for d in denied} >= {
        ("test_viewer", "POST /api/settings/users (forbidden)"),
        ("test_analyst", "GET /api/audit (forbidden)"),
    }
    assert all(not d.success for d in denied)
    everything = " ".join(f"{a.actor} {a.action} {a.detail}" for a in db_session.query(AuditLog).all())
    assert secret not in everything and "mallory" not in everything


def test_me_lists_permissions_for_the_ui(client, tokens):
    for role, expected in (("viewer", VIEWER_ACTIONS), ("analyst", ANALYST_ACTIONS), ("admin", ADMIN_ACTIONS)):
        assert set(client.get("/api/auth/me", headers=tokens[role]).json()["permissions"]) == expected
