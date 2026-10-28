from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.audit import log_action, verify_audit_chain
from app.auth.routes import LOGIN_THRESHOLD
from app.config import settings
from app.export_quota import consume_export_quota
from app.main import app
from app.models import AuditLog, LoginFailure, User


def _login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_lockout_has_backoff_and_success_resets(client, seed_users, db_session):
    for _ in range(LOGIN_THRESHOLD):
        assert _login(client, "test_analyst", "incorrect").status_code == 401
    row = db_session.get(LoginFailure, "test_analyst")
    assert row is not None and row.locked_until is not None
    first_cooldown = row.locked_until

    # A correct password is still refused during lockout, with the same generic response.
    blocked = _login(client, "test_analyst", "TestAnalystPass123!")
    assert blocked.status_code == 401
    assert blocked.json()["detail"] == "Invalid username or password"

    row.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    db_session.commit()
    assert _login(client, "test_analyst", "incorrect").status_code == 401
    row = db_session.get(LoginFailure, "test_analyst")
    assert row.locked_until > first_cooldown

    row.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    db_session.commit()
    assert _login(client, "test_analyst", "TestAnalystPass123!").status_code == 200
    assert db_session.get(LoginFailure, "test_analyst") is None


def test_logout_revokes_token_immediately(client, seed_users):
    response = _login(client, "test_analyst", "TestAnalystPass123!")
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_export_quota_blocks_and_audits(monkeypatch, db_session):
    monkeypatch.setattr(settings, "export_quota_count", 1)
    monkeypatch.setattr(settings, "export_quota_minutes", 60)
    consume_export_quota(db_session, "analyst", "test CSV")
    with pytest.raises(HTTPException) as error:
        consume_export_quota(db_session, "analyst", "test CSV")
    assert error.value.status_code == 429
    entry = db_session.query(AuditLog).filter_by(action="export_quota_alert").one()
    assert entry.actor == "analyst" and not entry.success


def test_audit_chain_detects_edits_and_tail_deletion(db_session):
    log_action(db_session, "admin", "test_event", "safe detail")
    assert verify_audit_chain(db_session) == (True, None)

    entry = db_session.query(AuditLog).one()
    entry.detail = "altered"
    db_session.commit()
    assert verify_audit_chain(db_session)[0] is False

    db_session.rollback()
    db_session.query(AuditLog).delete()
    db_session.commit()
    assert verify_audit_chain(db_session)[0] is False


def test_mfa_secret_is_encrypted_in_database(db_session, seed_users):
    user = db_session.query(User).filter_by(username="test_analyst").one()
    user.mfa_secret = "JBSWY3DPEHPK3PXP"
    db_session.commit()
    stored = db_session.execute(
        text("SELECT mfa_secret FROM users WHERE username = 'test_analyst'")
    ).scalar_one()
    assert stored.startswith("gAAAA")
    db_session.expire(user, ["mfa_secret"])
    assert user.mfa_secret == "JBSWY3DPEHPK3PXP"


def test_api_docs_are_not_registered_outside_development(client):
    assert settings.app_env == "test"
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
    # The in-process schema remains available to permission-matrix checks.
    assert "/api/auth/logout" in app.openapi()["paths"]
