import httpx
import pytest

from app.config import settings
from app.models import AuditLog, User
from tests.test_detection_routes import _brute_force_events

BRUTE_FORCE_RULE_ID = "8b596fb9-4145-48d7-907e-b16ed8c185a6"
COLLECTOR_HEADERS = {"X-Collector-Key": "test-collector-key"}


def _login(client, username, password):
    token = client.post("/api/auth/login", json={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin(client, seed_users):
    return _login(client, "test_admin", "TestAdminPass123!")


def _user_id(client, admin, username):
    return next(u["id"] for u in client.get("/api/settings/users", headers=admin).json() if u["username"] == username)


def _audit_actions(db_session):
    return [a.action for a in db_session.query(AuditLog).all()]


# ---------- RBAC ----------

ADMIN_ROUTES = [
    ("get", "/api/settings/users", None),
    ("post", "/api/settings/users", {"username": "x_user", "password": "LongEnoughPass1", "role": "viewer"}),
    ("patch", "/api/settings/users/any", {"role": "admin"}),
    ("post", "/api/settings/users/any/reset-password", {"new_password": "LongEnoughPass1"}),
    ("get", "/api/settings/rules", None),
    ("patch", f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", {"enabled": False}),
    ("get", "/api/settings/system", None),
    ("put", "/api/settings/system", {"ai_calls_per_hour": 5}),
]


@pytest.mark.parametrize("username,password", [("test_analyst", "TestAnalystPass123!"), ("test_viewer", "TestViewerPass123!")])
@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_non_admins_get_403(client, seed_users, username, password, method, path, body):
    headers = _login(client, username, password)
    resp = client.request(method, path, headers=headers, json=body)
    assert resp.status_code == 403


def test_unauthenticated_gets_401(client):
    assert client.get("/api/settings/users").status_code == 401


# ---------- Users ----------


def test_list_users_never_exposes_hashes(client, admin):
    resp = client.get("/api/settings/users", headers=admin)
    assert resp.status_code == 200
    assert "password_hash" not in resp.text and "$argon2" not in resp.text
    assert {u["username"] for u in resp.json()} == {"test_admin", "test_analyst", "test_viewer"}


def test_create_user_hashes_with_argon2_and_audits(client, admin, db_session):
    resp = client.post("/api/settings/users", headers=admin, json={"username": "new_analyst", "password": "BrandNewPass123", "role": "analyst"})
    assert resp.status_code == 201
    assert resp.json()["role"] == "analyst" and "password" not in resp.text
    assert db_session.query(User).filter_by(username="new_analyst").one().password_hash.startswith("$argon2")
    assert "user_create" in _audit_actions(db_session)
    assert client.post("/api/auth/login", json={"username": "new_analyst", "password": "BrandNewPass123"}).status_code == 200


def test_create_user_rejects_duplicate_short_password_and_bad_role(client, admin):
    assert client.post("/api/settings/users", headers=admin, json={"username": "test_viewer", "password": "BrandNewPass123"}).status_code == 409
    assert client.post("/api/settings/users", headers=admin, json={"username": "shorty", "password": "short"}).status_code == 422
    assert client.post("/api/settings/users", headers=admin, json={"username": "boss", "password": "BrandNewPass123", "role": "root"}).status_code == 422


def test_change_role_takes_effect_immediately(client, admin, db_session):
    viewer = _login(client, "test_viewer", "TestViewerPass123!")
    assert client.get("/api/settings/users", headers=viewer).status_code == 403
    resp = client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_viewer')}", headers=admin, json={"role": "admin"})
    assert resp.status_code == 200
    # Same token, role is read from the DB on each request.
    assert client.get("/api/settings/users", headers=viewer).status_code == 200
    assert "user_update" in _audit_actions(db_session)


def test_disabled_user_cannot_log_in_or_use_existing_token(client, admin):
    analyst = _login(client, "test_analyst", "TestAnalystPass123!")
    client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_analyst')}", headers=admin, json={"is_active": False})

    assert client.get("/api/auth/me", headers=analyst).status_code == 401
    resp = client.post("/api/auth/login", json={"username": "test_analyst", "password": "TestAnalystPass123!"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password"  # generic, no account-state leak

    client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_analyst')}", headers=admin, json={"is_active": True})
    assert client.post("/api/auth/login", json={"username": "test_analyst", "password": "TestAnalystPass123!"}).status_code == 200


@pytest.mark.parametrize("change", [{"role": "analyst"}, {"is_active": False}])
def test_cannot_demote_or_disable_last_admin(client, admin, db_session, change):
    resp = client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_admin')}", headers=admin, json=change)
    assert resp.status_code == 400
    assert db_session.query(AuditLog).filter_by(action="user_update", success=False).count() == 1


def test_can_demote_admin_when_another_admin_exists(client, admin):
    client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_analyst')}", headers=admin, json={"role": "admin"})
    resp = client.patch(f"/api/settings/users/{_user_id(client, admin, 'test_admin')}", headers=admin, json={"role": "viewer"})
    assert resp.status_code == 200


def test_reset_password(client, admin, db_session):
    user_id = _user_id(client, admin, "test_viewer")
    assert client.post(f"/api/settings/users/{user_id}/reset-password", headers=admin, json={"new_password": "ResetPassword123"}).status_code == 204
    assert client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "test_viewer", "password": "ResetPassword123"}).status_code == 200
    assert "user_password_reset" in _audit_actions(db_session)


def test_unknown_user_404(client, admin):
    assert client.patch("/api/settings/users/nope", headers=admin, json={"role": "viewer"}).status_code == 404


# ---------- Detection rules ----------


def _brute_force_detections(client, headers):
    return [d for d in client.get("/api/detections", headers=headers).json() if d["rule_name"] == "Brute force logon"]


def test_list_rules(client, admin):
    rules = client.get("/api/settings/rules", headers=admin).json()
    bf = next(r for r in rules if r["id"] == BRUTE_FORCE_RULE_ID)
    assert bf["enabled"] and bf["min_count"] == 5 and bf["window_minutes"] == 5


def test_disable_rule_applies_on_next_detection_run(client, admin, db_session):
    client.post("/api/events/ingest", json={"events": _brute_force_events()}, headers=COLLECTOR_HEADERS)
    assert len(_brute_force_detections(client, admin)) == 1

    resp = client.patch(f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", headers=admin, json={"enabled": False})
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    assert _brute_force_detections(client, admin) == []
    assert "rule_update" in _audit_actions(db_session)

    client.patch(f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", headers=admin, json={"enabled": True})
    assert len(_brute_force_detections(client, admin)) == 1


def test_raise_brute_force_threshold_applies_on_next_run(client, admin):
    client.post("/api/events/ingest", json={"events": _brute_force_events()}, headers=COLLECTOR_HEADERS)
    resp = client.patch(f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", headers=admin, json={"min_count": 6, "window_minutes": 10})
    assert resp.json()["min_count"] == 6 and resp.json()["window_minutes"] == 10
    assert _brute_force_detections(client, admin) == []  # only 5 failures now


def test_rule_threshold_validation(client, admin):
    assert client.patch(f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", headers=admin, json={"min_count": 0}).status_code == 422
    assert client.patch(f"/api/settings/rules/{BRUTE_FORCE_RULE_ID}", headers=admin, json={"window_minutes": 99999}).status_code == 422
    filter_rule = next(r for r in client.get("/api/settings/rules", headers=admin).json() if r["kind"] == "filter")
    assert client.patch(f"/api/settings/rules/{filter_rule['id']}", headers=admin, json={"min_count": 3}).status_code == 400
    assert client.patch("/api/settings/rules/unknown", headers=admin, json={"enabled": False}).status_code == 404


# ---------- System ----------


def test_system_status_template_provider(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "template")
    assert client.get("/api/settings/system", headers=admin).json()["collector_last_seen"] is None

    client.post("/api/events/ingest", json={"events": _brute_force_events()}, headers=COLLECTOR_HEADERS)
    body = client.get("/api/settings/system", headers=admin).json()
    assert body["collector_last_seen"] is not None
    assert body["ollama"] is None
    assert body["ai_calls_per_hour"] == settings.ai_calls_per_hour


def test_system_status_ollama_unreachable(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")

    def fail(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", fail)
    body = client.get("/api/settings/system", headers=admin).json()
    assert body["ollama"] == {"reachable": False, "model_installed": False, "model_loaded": False}


def test_system_status_ollama_model_loaded(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    models = {"models": [{"name": settings.llm_model}]}
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Response(200, json=models, request=httpx.Request("GET", url)))
    body = client.get("/api/settings/system", headers=admin).json()
    assert body["ollama"] == {"reachable": True, "model_installed": True, "model_loaded": True}


def test_update_ai_cap_is_stored_and_audited(client, admin, db_session):
    assert client.put("/api/settings/system", headers=admin, json={"ai_calls_per_hour": 3}).status_code == 204
    assert client.get("/api/settings/system", headers=admin).json()["ai_calls_per_hour"] == 3
    assert "system_update" in _audit_actions(db_session)
    assert client.put("/api/settings/system", headers=admin, json={"ai_calls_per_hour": 0}).status_code == 422
