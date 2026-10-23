"""Smoke test: every GET route, called as admin / analyst / viewer.

Asserts no 5xx, no stack trace in the body, and that role rules hold:
admin-only routes give 403 to analyst and viewer, analyst routes give 403 to viewer,
and everything else is readable by every logged-in role.
"""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.main import app
from app.models import Event

PASSWORDS = {"admin": "TestAdminPass123!", "analyst": "TestAnalystPass123!", "viewer": "TestViewerPass123!"}

ADMIN_ONLY_PREFIXES = ("/api/audit", "/api/settings")
ADMIN_ANALYST = {"/api/incidents/{incident_id}/scripts/{kind}"}
PUBLIC = {"/api/health"}

TRACE_MARKERS = ("Traceback", 'File "', "sqlalchemy.exc", "Exception:")


def _get_routes() -> list[str]:
    # Read from the OpenAPI schema: this FastAPI version wraps included routers,
    # so app.routes does not list the individual APIRoutes.
    return sorted(path for path, ops in app.openapi()["paths"].items() if "get" in ops)


def _allowed_roles(path: str) -> set[str]:
    if path.startswith(ADMIN_ONLY_PREFIXES):
        return {"admin"}
    if path in ADMIN_ANALYST:
        return {"admin", "analyst"}
    return {"admin", "analyst", "viewer"}


@pytest.fixture()
def tokens(client, seed_users):
    out = {}
    for role, password in PASSWORDS.items():
        resp = client.post("/api/auth/login", json={"username": f"test_{role}", "password": password})
        out[role] = {"Authorization": f"Bearer {resp.json()['access_token']}"}
    return out


@pytest.fixture()
def incident_id(client, tokens, db_session):
    # One "audit log cleared" event (T1070.001) is enough to produce an incident.
    db_session.add(Event(
        id="smoke-1102", source="local", host="PC1", timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
        channel="Security", provider="Microsoft-Windows-Eventlog", event_id=1102, user="bob",
        message="The audit log was cleared.", raw=json.dumps({}),
    ))
    db_session.commit()
    incidents = client.get("/api/incidents", headers=tokens["admin"]).json()
    assert incidents, "seed event should create an incident"
    return incidents[0]["id"]


def _fill(path: str, incident_id: str, rule_id: str) -> str:
    values = {"incident_id": incident_id, "kind": "firewall", "technique_id": "T1070.001", "rule_id": rule_id}
    return re.sub(r"\{(\w+)\}", lambda m: values[m.group(1)], path)


def test_route_list_is_not_empty():
    assert len(_get_routes()) >= 20


def test_every_get_route_per_role(client, tokens, incident_id):
    rules = client.get("/api/settings/rules", headers=tokens["admin"]).json()
    rule_id = rules[0]["id"]
    problems = []
    for path in _get_routes():
        url = _fill(path, incident_id, rule_id)
        for role, headers in tokens.items():
            resp = client.get(url, headers=headers)
            body = resp.text
            if resp.status_code >= 500:
                problems.append(f"{role} {url}: {resp.status_code}")
            if any(marker in body for marker in TRACE_MARKERS):
                problems.append(f"{role} {url}: stack trace in body")
            if path in PUBLIC:
                continue
            allowed = role in _allowed_roles(path)
            if allowed and resp.status_code in (401, 403):
                problems.append(f"{role} {url}: expected access, got {resp.status_code}")
            if not allowed and resp.status_code != 403:
                problems.append(f"{role} {url}: expected 403, got {resp.status_code}")
    assert not problems, "\n".join(problems)


def test_every_get_route_needs_login(client):
    for path in _get_routes():
        if path in PUBLIC:
            continue
        url = _fill(path, "x", "x")
        assert client.get(url).status_code == 401, url
