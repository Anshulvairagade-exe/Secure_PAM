"""
Authentication: dev login, /me, invalid credentials, unauthorized access,
and the core trust boundary between IdP identity and local RBAC.
"""

from httpx import AsyncClient

from tests.conftest import auth_header, issue_token


async def test_login_success_returns_tokens(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "operator123"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


async def test_login_wrong_password_returns_401_with_consistent_envelope(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "not-the-password"}
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["detail"] == "Invalid username or password"
    assert "error_code" in body  # consistent envelope, even though null here


async def test_login_unknown_username_returns_401(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "no-such-user", "password": "x"}
    )
    assert resp.status_code == 401


async def test_login_missing_fields_returns_422_validation_error(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error_code"] == "VALIDATION_ERROR"
    fields = {tuple(e["loc"]) for e in body["errors"]}
    assert ("body", "username") in fields
    assert ("body", "password") in fields


async def test_me_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"


async def test_me_rejects_garbage_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me", headers=auth_header("not-a-real-jwt"))
    assert resp.status_code == 401


async def test_me_returns_profile_and_permissions(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/v1/auth/me", headers=auth_header(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "admin"
    assert "ADMIN" in body["roles"]
    assert "assets:read" in body["permissions"]


async def test_token_claimed_roles_are_not_trusted(client: AsyncClient):
    """
    Core security property from the auth architecture (app/auth/base.py):
    TokenIdentity.token_roles is informational ONLY. Authorization always
    comes from the local RBAC tables, never from what a token claims.

    Here we mint a token for the 'operator' user but forge ADMIN into its
    token_roles claim. /me must still report OPERATOR — proving the forged
    claim was never consulted.
    """
    forged_token = issue_token("operator", roles=["ADMIN"])
    resp = await client.get("/api/v1/auth/me", headers=auth_header(forged_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["roles"] == ["OPERATOR"]
    assert "users:delete" not in body["permissions"]


async def test_login_disabled_outside_dev_mode(client: AsyncClient, monkeypatch):
    from app.api.v1 import auth as auth_module

    monkeypatch.setattr(auth_module.settings, "DEV_MODE", False)
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "operator123"}
    )
    assert resp.status_code == 403
