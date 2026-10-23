from datetime import datetime, timedelta, timezone

import jwt

from app.auth import totp
from app.auth.security import create_mfa_token
from app.config import settings
from app.models import AuditLog, User


def _login(client, username="test_analyst", password="TestAnalystPass123!"):
    return client.post("/api/auth/login", json={"username": username, "password": password}).json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _enable_mfa(client, db_session, now=None):
    """Enrol test_analyst. Returns (secret, recovery_codes). The confirmation code is
    taken from the previous time step so a fresh current-step code is still usable."""
    token = _login(client)["access_token"]
    secret = client.post("/api/auth/mfa/setup", headers=_auth(token)).json()["secret"]
    prev_code = totp.totp(secret, (now or datetime.now().timestamp()) - totp.STEP_SECONDS)
    resp = client.post("/api/auth/mfa/enable", json={"code": prev_code}, headers=_auth(token))
    assert resp.status_code == 200
    return secret, resp.json()["recovery_codes"]


def test_rfc6238_sha1_vector():
    # RFC 6238 Appendix B, SHA1 key "12345678901234567890", T=59 -> 94287082 (last 6 digits).
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.totp(secret, 59) == "287082"
    assert totp.totp(secret, 1111111109) == "081804"


def test_existing_users_have_mfa_off(client, seed_users):
    body = _login(client)
    assert body["access_token"]
    assert not body.get("mfa_required")


def test_enable_returns_eight_single_view_recovery_codes(client, seed_users, db_session):
    _, codes = _enable_mfa(client, db_session)
    assert len(codes) == 8 and len(set(codes)) == 8
    user = db_session.query(User).filter_by(username="test_analyst").one()
    db_session.refresh(user)
    assert user.mfa_enabled
    assert all(c not in user.mfa_recovery_codes for c in codes)  # only hashes stored
    assert "$argon2" in user.mfa_recovery_codes


def test_login_requires_second_step_and_correct_code(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    body = _login(client)
    assert body["mfa_required"] is True and "access_token" not in body

    wrong = client.post("/api/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": "000000"})
    if totp.totp(secret) != "000000":
        assert wrong.status_code == 401

    ok = client.post("/api/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": totp.totp(secret)})
    assert ok.status_code == 200
    assert client.get("/api/auth/me", headers=_auth(ok.json()["access_token"])).status_code == 200


def test_replayed_code_rejected(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    code = totp.totp(secret)
    first = client.post("/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": code})
    assert first.status_code == 200
    replay = client.post("/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": code})
    assert replay.status_code == 401


def test_enrolment_code_cannot_be_reused_to_log_in(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    prev_code = totp.totp(secret, datetime.now().timestamp() - totp.STEP_SECONDS)
    resp = client.post("/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": prev_code})
    assert resp.status_code == 401


def test_expired_mfa_token_rejected(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    expired = jwt.encode(
        {"sub": "test_analyst", "purpose": "mfa", "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    resp = client.post("/api/auth/mfa/verify", json={"mfa_token": expired, "code": totp.totp(secret)})
    assert resp.status_code == 401


def test_mfa_token_cannot_access_other_routes(client, seed_users, db_session):
    _enable_mfa(client, db_session)
    mfa_token = _login(client)["mfa_token"]
    for path in ("/api/auth/me", "/api/events", "/api/incidents", "/api/auth/mfa"):
        assert client.get(path, headers=_auth(mfa_token)).status_code == 401
    assert client.post("/api/auth/mfa/setup", headers=_auth(mfa_token)).status_code == 401


def test_access_token_not_accepted_as_mfa_token(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    access = _login(client, "test_admin", "TestAdminPass123!")["access_token"]
    # Even for the right user, an access token is the wrong purpose.
    resp = client.post("/api/auth/mfa/verify", json={"mfa_token": access, "code": totp.totp(secret)})
    assert resp.status_code == 401


def test_recovery_code_is_single_use(client, seed_users, db_session):
    _, codes = _enable_mfa(client, db_session)
    first = client.post("/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": codes[0]})
    assert first.status_code == 200
    again = client.post("/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": codes[0]})
    assert again.status_code == 401
    status = client.get("/api/auth/mfa", headers=_auth(first.json()["access_token"])).json()
    assert status == {"enabled": True, "recovery_codes_left": 7}


def test_disable_needs_password_and_code(client, seed_users, db_session):
    secret, _ = _enable_mfa(client, db_session)
    token = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": _login(client)["mfa_token"], "code": totp.totp(secret)}
    ).json()["access_token"]
    next_code = totp.totp(secret, datetime.now().timestamp() + totp.STEP_SECONDS)

    bad = client.post("/api/auth/mfa/disable", json={"password": "wrong", "code": next_code}, headers=_auth(token))
    assert bad.status_code == 400
    ok = client.post("/api/auth/mfa/disable", json={"password": "TestAnalystPass123!", "code": next_code}, headers=_auth(token))
    assert ok.status_code == 204
    assert "access_token" in _login(client)


def test_admin_can_reset_mfa_and_events_are_audited(client, seed_users, db_session):
    _enable_mfa(client, db_session)
    assert _login(client)["mfa_required"] is True
    admin = _login(client, "test_admin", "TestAdminPass123!")["access_token"]
    analyst_id = db_session.query(User).filter_by(username="test_analyst").one().id

    viewer = _login(client, "test_viewer", "TestViewerPass123!")["access_token"]
    assert client.post(f"/api/settings/users/{analyst_id}/reset-mfa", headers=_auth(viewer)).status_code == 403
    # MFA reset is a step-up action: refused until the admin re-enters their password.
    assert client.post(f"/api/settings/users/{analyst_id}/reset-mfa", headers=_auth(admin)).status_code == 403
    assert client.post("/api/auth/step-up", json={"password": "TestAdminPass123!"}, headers=_auth(admin)).status_code == 204
    assert client.post(f"/api/settings/users/{analyst_id}/reset-mfa", headers=_auth(admin)).status_code == 204
    assert "access_token" in _login(client)

    actions = {a for (a,) in db_session.query(AuditLog.action).all()}
    assert {"mfa_setup_started", "mfa_enable", "mfa_challenge", "mfa_reset"} <= actions


def test_verify_without_mfa_enabled_fails(client, seed_users):
    token = create_mfa_token("test_analyst")  # user has MFA off
    resp = client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": "123456"})
    assert resp.status_code == 401
