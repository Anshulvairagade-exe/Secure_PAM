"""Admin user create/edit: identity rules per auth mode, uniqueness, no secrets leaked, RBAC, auditing."""

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.audit import AuditLog
from app.models.role import Role
from app.models.user import User
from tests.conftest import auth_header

PW = "PW-CANARY-user-create-123"
KC_ID = "0b6f3f3c-5d1e-4c1b-9a4e-2f8f3c1d2e10"


async def _role_id(db, name):
    return str((await db.execute(select(Role).where(Role.name == name))).scalar_one().id)


async def test_dev_mode_creates_local_account_with_hashed_password(client, db_session, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "DEV_MODE", True)
    r = await client.post("/api/v1/users", headers=auth_header(admin_token), json={
        "username": "New.Operator", "email": "new.op@example.com", "full_name": "New Operator", "password": PW,
        "role_ids": [await _role_id(db_session, "OPERATOR")]})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["username"] == "new.operator" and [x["name"] for x in body["roles"]] == ["OPERATOR"]
    assert body["identity_source"] == "development account" and PW not in r.text
    user = (await db_session.execute(select(User).where(User.username == "new.operator"))).scalar_one()
    assert user.hashed_password and PW not in user.hashed_password
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "USER_CREATED"))).scalar_one()
    assert PW not in str(audit.details) and audit.details["roles"] == ["OPERATOR"]
    # the new account can sign in with that password
    login = await client.post("/api/v1/auth/login", json={"username": "new.operator", "password": PW})
    assert login.status_code == 200


async def test_keycloak_mode_requires_subject_id_and_refuses_passwords(client, db_session, admin_token, monkeypatch):
    import app.api.v1.users as users_api
    monkeypatch.setattr(users_api, "_local_accounts", lambda: False)
    base = {"username": "kc.user", "email": "kc.user@example.com", "full_name": "KC User"}
    r = await client.post("/api/v1/users", headers=auth_header(admin_token), json=base)
    assert r.status_code == 422 and "Keycloak" in r.json()["detail"]
    r = await client.post("/api/v1/users", headers=auth_header(admin_token), json={**base, "external_id": KC_ID, "password": PW})
    assert r.status_code == 422 and PW not in r.text
    r = await client.post("/api/v1/users", headers=auth_header(admin_token), json={**base, "external_id": "not-a-uuid"})
    assert r.status_code == 422
    r = await client.post("/api/v1/users", headers=auth_header(admin_token), json={**base, "external_id": KC_ID.upper()})
    assert r.status_code == 201 and r.json()["external_id"] == KC_ID and r.json()["identity_source"] == "identity provider"


async def test_duplicates_rejected(client, db_session, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "DEV_MODE", True)
    body = {"username": "dup.user", "email": "dup@example.com", "full_name": "Dup", "password": PW}
    assert (await client.post("/api/v1/users", headers=auth_header(admin_token), json=body)).status_code == 201
    assert (await client.post("/api/v1/users", headers=auth_header(admin_token), json=body)).status_code == 409
    other = {**body, "username": "dup.user2"}
    assert (await client.post("/api/v1/users", headers=auth_header(admin_token), json=other)).status_code == 409


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token", "auditor_token"])
async def test_only_admins_create_or_edit(client, db_session, request, token_fixture, monkeypatch):
    monkeypatch.setattr(settings, "DEV_MODE", True)
    h = auth_header(request.getfixturevalue(token_fixture))
    r = await client.post("/api/v1/users", headers=h, json={
        "username": "escalate", "email": "esc@example.com", "full_name": "E", "password": PW,
        "role_ids": [await _role_id(db_session, "ADMIN")]})
    assert r.status_code == 403
    assert (await db_session.execute(select(User).where(User.username == "escalate"))).scalar_one_or_none() is None
    target = (await db_session.execute(select(User).where(User.username == "operator"))).scalar_one()
    assert (await client.patch(f"/api/v1/users/{target.id}", headers=h, json={"full_name": "x"})).status_code == 403


async def test_edit_profile_and_link_identity_rules(client, db_session, admin_token):
    target = (await db_session.execute(select(User).where(User.username == "operator"))).scalar_one()
    r = await client.patch(f"/api/v1/users/{target.id}", headers=auth_header(admin_token),
                           json={"full_name": "Operator Renamed", "email": "operator.new@example.com"})
    assert r.status_code == 200 and r.json()["full_name"] == "Operator Renamed"
    if target.external_id is None:
        r = await client.patch(f"/api/v1/users/{target.id}", headers=auth_header(admin_token), json={"external_id": KC_ID})
        assert r.status_code == 200 and r.json()["external_id"] == KC_ID
    r = await client.patch(f"/api/v1/users/{target.id}", headers=auth_header(admin_token),
                           json={"external_id": "11111111-2222-3333-4444-555555555555"})
    assert r.status_code == 409  # never silently re-point an account at another identity
    me = (await db_session.execute(select(User).where(User.username == "admin"))).scalar_one()
    if me.external_id is None:
        r = await client.patch(f"/api/v1/users/{me.id}", headers=auth_header(admin_token),
                               json={"external_id": "11111111-2222-3333-4444-555555555555"})
        assert r.status_code == 409
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "USER_UPDATED"))).scalars().all()
    assert audit and "full_name" in audit[0].details["changed_fields"]
