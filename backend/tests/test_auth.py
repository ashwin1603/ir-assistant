def test_login_success(client, seed_users):
    resp = client.post("/api/auth/login", json={"username": "test_admin", "password": "TestAdminPass123!"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin"
    assert body["access_token"]


def test_login_wrong_password(client, seed_users):
    resp = client.post("/api/auth/login", json={"username": "test_admin", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password"


def test_login_unknown_user_same_error_as_wrong_password(client, seed_users):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password"


def test_me_requires_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_with_valid_token(client, seed_users):
    login = client.post("/api/auth/login", json={"username": "test_analyst", "password": "TestAnalystPass123!"})
    token = login.json()["access_token"]
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert (body["username"], body["role"]) == ("test_analyst", "analyst")
    # /me also lists what the role may do, so the UI can hide controls (enforcement stays server-side).
    assert "upload" in body["permissions"] and "manage_users" not in body["permissions"]


def test_audit_log_rejects_non_admin(client, seed_users):
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    token = login.json()["access_token"]
    resp = client.get("/api/audit", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_audit_log_records_failed_and_successful_logins(client, seed_users):
    client.post("/api/auth/login", json={"username": "test_admin", "password": "wrong"})
    login = client.post("/api/auth/login", json={"username": "test_admin", "password": "TestAdminPass123!"})
    token = login.json()["access_token"]

    resp = client.get("/api/audit", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    entries = resp.json()["items"]
    login_entries = [e for e in entries if e["action"] == "login" and e["actor"] == "test_admin"]
    assert any(e["success"] is False for e in login_entries)
    assert any(e["success"] is True for e in login_entries)
