"""Step-up re-authentication, "Require MFA for admin", and scripts/admin_recovery.py."""

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.auth import totp
from app.auth.security import create_mfa_setup_token, verify_password
from app.auth.step_up import STEP_UP_REQUIRED, has_recent_step_up
from app.models import AuditLog, User

ADMIN_PW = "TestAdminPass123!"
VALID_SIGMA = """
title: Certutil download
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image|endswith: '\\\\certutil.exe', CommandLine|contains: 'urlcache'}
  condition: sel
level: high
tags: [attack.t1105]
"""


def _login(client, username="test_admin", password=ADMIN_PW):
    return client.post("/api/auth/login", json={"username": username, "password": password}).json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin(client, seed_users):
    return _auth(_login(client)["access_token"])


def _user_id(db_session, username):
    return db_session.query(User).filter_by(username=username).one().id


def _step_up_routes(db_session):
    uid = _user_id(db_session, "test_viewer")
    return [
        ("POST", "/api/settings/users", {"username": "newbie", "password": "LongEnoughPass1!", "role": "viewer"}),
        ("PATCH", f"/api/settings/users/{uid}", {"role": "analyst"}),
        ("PATCH", f"/api/settings/users/{uid}", {"is_active": False}),
        ("POST", f"/api/settings/users/{uid}/reset-password", {"new_password": "AnotherLongPass1!"}),
        ("POST", f"/api/settings/users/{uid}/reset-mfa", None),
        ("POST", "/api/settings/rules/import-sigma", {"yaml": VALID_SIGMA}),
    ]


# ---------- step-up ----------


def test_sensitive_admin_actions_need_step_up(client, admin, db_session):
    for method, url, body in _step_up_routes(db_session):
        resp = client.request(method, url, headers=admin, json=body)
        assert resp.status_code == 403, f"{method} {url}"
        assert resp.json()["detail"] == STEP_UP_REQUIRED
    denied = db_session.query(AuditLog).filter(AuditLog.action == "access_denied").all()
    assert len(denied) == 6 and all("step-up required" in d.detail for d in denied)


def test_step_up_with_password_unlocks_them(client, admin, db_session):
    assert client.post("/api/auth/step-up", json={"password": ADMIN_PW}, headers=admin).status_code == 204
    for method, url, body in _step_up_routes(db_session):
        if "import-sigma" in url:
            continue  # import writes a rule file; its own tests cover it with an isolated rules dir
        resp = client.request(method, url, headers=admin, json=body)
        assert resp.status_code in (200, 201, 204), f"{method} {url}: {resp.status_code}"
    assert "step_up" in {a for (a,) in db_session.query(AuditLog.action).all()}


def test_wrong_password_does_not_step_up(client, admin, db_session):
    assert client.post("/api/auth/step-up", json={"password": "wrong"}, headers=admin).status_code == 400
    assert client.post("/api/auth/step-up", json={}, headers=admin).status_code == 400
    uid = _user_id(db_session, "test_viewer")
    assert client.post(f"/api/settings/users/{uid}/reset-mfa", headers=admin).status_code == 403


def test_step_up_expires_after_five_minutes(seed_users, db_session):
    user = db_session.query(User).filter_by(username="test_admin").one()
    now = datetime.now(timezone.utc)
    user.step_up_at = now - timedelta(minutes=4, seconds=59)
    assert has_recent_step_up(user, now)
    user.step_up_at = now - timedelta(minutes=5)
    assert not has_recent_step_up(user, now)
    user.step_up_at = (now - timedelta(minutes=1)).replace(tzinfo=None)  # SQLite returns naive UTC
    assert has_recent_step_up(user, now)


def test_step_up_is_per_user(client, admin, seed_users, db_session):
    # The analyst stepping up does not help anyone else, and analysts still can't manage users.
    analyst = _auth(_login(client, "test_analyst", "TestAnalystPass123!")["access_token"])
    assert client.post("/api/auth/step-up", json={"password": "TestAnalystPass123!"}, headers=analyst).status_code == 204
    uid = _user_id(db_session, "test_viewer")
    assert client.post(f"/api/settings/users/{uid}/reset-mfa", headers=analyst).status_code == 403
    assert client.post(f"/api/settings/users/{uid}/reset-mfa", headers=admin).status_code == 403


def _enable_mfa(client, headers):
    secret = client.post("/api/auth/mfa/setup", headers=headers).json()["secret"]
    resp = client.post("/api/auth/mfa/enable", json={"code": totp.totp(secret)}, headers=headers)
    assert resp.status_code == 200
    return secret, resp.json()


def test_mfa_user_must_step_up_with_a_code_not_the_password(client, admin, db_session):
    secret, _ = _enable_mfa(client, admin)  # existing token stays valid
    assert client.post("/api/auth/step-up", json={"password": ADMIN_PW}, headers=admin).status_code == 400
    next_code = totp.totp(secret, datetime.now().timestamp() + totp.STEP_SECONDS)
    assert client.post("/api/auth/step-up", json={"code": next_code}, headers=admin).status_code == 204
    uid = _user_id(db_session, "test_viewer")
    assert client.post(f"/api/settings/users/{uid}/reset-mfa", headers=admin).status_code == 204


# ---------- Require MFA for admin ----------


def test_require_admin_mfa_defaults_off(client, admin):
    assert client.get("/api/settings/system", headers=admin).json()["require_admin_mfa"] is False
    assert "access_token" in _login(client)


def test_require_admin_mfa_forces_setup_at_login(client, admin, db_session):
    assert client.put("/api/settings/system", json={"require_admin_mfa": True}, headers=admin).status_code == 204
    assert client.get("/api/settings/system", headers=admin).json()["require_admin_mfa"] is True

    first = _login(client)
    assert first.get("mfa_setup_required") is True and "access_token" not in first
    setup_token = _auth(first["mfa_token"])

    # The setup token works only for MFA enrolment, nowhere else.
    assert client.get("/api/auth/me", headers=setup_token).status_code == 401
    assert client.get("/api/incidents", headers=setup_token).status_code == 401
    assert client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": "123456"}).status_code == 401

    secret, enabled = _enable_mfa(client, setup_token)
    assert enabled["access_token"] and enabled["role"] == "admin" and len(enabled["recovery_codes"]) == totp.RECOVERY_CODE_COUNT
    assert client.get("/api/auth/me", headers=_auth(enabled["access_token"])).status_code == 200

    # From now on it's the normal password + code login.
    assert _login(client).get("mfa_required") is True
    actions = {a for (a,) in db_session.query(AuditLog.action).all()}
    assert {"mfa_setup_forced", "mfa_enable"} <= actions


def test_require_admin_mfa_does_not_affect_other_roles(client, admin):
    client.put("/api/settings/system", json={"require_admin_mfa": True}, headers=admin)
    assert "access_token" in _login(client, "test_analyst", "TestAnalystPass123!")
    assert "access_token" in _login(client, "test_viewer", "TestViewerPass123!")


def test_admin_cannot_disable_mfa_while_required(client, admin):
    secret, _ = _enable_mfa(client, admin)
    client.put("/api/settings/system", json={"require_admin_mfa": True}, headers=admin)
    code = totp.totp(secret, datetime.now().timestamp() + totp.STEP_SECONDS)
    resp = client.post("/api/auth/mfa/disable", json={"password": ADMIN_PW, "code": code}, headers=admin)
    assert resp.status_code == 400 and "required" in resp.json()["detail"]


def test_setup_token_is_rejected_where_an_access_token_is_needed(client, seed_users):
    token = _auth(create_mfa_setup_token("test_admin"))
    assert client.get("/api/settings/users", headers=token).status_code == 401
    assert client.post("/api/auth/step-up", json={"password": ADMIN_PW}, headers=token).status_code == 401


def test_viewer_cannot_change_the_setting(client, seed_users):
    viewer = _auth(_login(client, "test_viewer", "TestViewerPass123!")["access_token"])
    assert client.put("/api/settings/system", json={"require_admin_mfa": False}, headers=viewer).status_code == 403


# ---------- scripts/admin_recovery.py ----------


def _recovery_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "admin_recovery.py"
    spec = importlib.util.spec_from_file_location("admin_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_admin_recovery_resets_password_and_mfa(client, admin, db_session):
    _enable_mfa(client, admin)
    user = db_session.query(User).filter_by(username="test_admin").one()
    user.is_active = False
    db_session.commit()

    recovery = _recovery_module()
    new_password = recovery.recover_admin(db_session, "test_admin")

    db_session.refresh(user)
    assert len(new_password) >= 20 and verify_password(new_password, user.password_hash)
    assert not verify_password(ADMIN_PW, user.password_hash)
    assert user.is_active and not user.mfa_enabled and user.mfa_secret is None
    # Audited, but the password is never written anywhere.
    rows = db_session.query(AuditLog).filter(AuditLog.action == "admin_recovery").all()
    assert len(rows) == 1 and new_password not in (rows[0].detail or "")
    assert "access_token" in _login(client, password=new_password)


def test_admin_recovery_refuses_non_admins(seed_users, db_session):
    recovery = _recovery_module()
    with pytest.raises(recovery.RecoveryError):
        recovery.recover_admin(db_session, "test_viewer")
    with pytest.raises(recovery.RecoveryError):
        recovery.recover_admin(db_session, "nobody")
