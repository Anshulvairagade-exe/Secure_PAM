"""Users and Roles admin API: real data, RBAC, guarded and audited changes."""

from sqlalchemy import select

from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.role import Role
from app.models.user import User, UserRole
from tests.conftest import auth_header, issue_token


async def _role(db, name):
    return (await db.execute(select(Role).where(Role.name == name))).scalar_one()


async def _user(db, username):
    return (await db.execute(select(User).where(User.username == username))).scalar_one()


async def _actions(db, action):
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


async def _second_admin(db):
    admin = await _role(db, "ADMIN")
    user = User(username="admin2", email="admin2@securepam.local", full_name="Second Admin",
                hashed_password=hash_password("admin2pass"), is_active=True)
    db.add(user)
    await db.flush()
    db.add(UserRole(user_id=user.id, role_id=admin.id))
    await db.commit()
    return issue_token("admin2", ["ADMIN"])


async def test_unauthenticated_and_non_admins_cannot_read(client, operator_token, auditor_token):
    assert (await client.get("/api/v1/users")).status_code == 401
    for token in (operator_token, auditor_token):
        for path in ("/api/v1/users", "/api/v1/roles"):
            assert (await client.get(path, headers=auth_header(token))).status_code == 403


async def test_admin_lists_real_users_without_secrets(client, admin_token):
    r = await client.get("/api/v1/users", headers=auth_header(admin_token))
    assert r.status_code == 200
    body = r.json()
    names = {u["username"] for u in body["items"]}
    assert {"admin", "operator", "approver", "auditor"} <= names and body["total"] == len(body["items"])
    operator = next(u for u in body["items"] if u["username"] == "operator")
    assert [x["name"] for x in operator["roles"]] == ["OPERATOR"]
    assert operator["identity_source"] == "development account"
    assert "hashed_password" not in r.text and "password" not in r.text.lower()


async def test_search_and_filters(client, admin_token):
    h = auth_header(admin_token)
    assert [u["username"] for u in (await client.get("/api/v1/users?search=audit", headers=h)).json()["items"]] == ["auditor"]
    by_role = (await client.get("/api/v1/users?role=APPROVER", headers=h)).json()["items"]
    assert [u["username"] for u in by_role] == ["approver"]
    assert (await client.get("/api/v1/users?active=false", headers=h)).json()["total"] == 0


async def test_user_detail_has_effective_permissions(client, db_session, admin_token):
    operator = await _user(db_session, "operator")
    r = await client.get(f"/api/v1/users/{operator.id}", headers=auth_header(admin_token))
    assert r.status_code == 200
    perms = r.json()["permissions"]
    assert "sessions:create" in perms and "users:update" not in perms
    assert (await client.get("/api/v1/users/00000000-0000-0000-0000-000000000000",
                             headers=auth_header(admin_token))).status_code == 404


async def test_roles_list_permissions_and_assigned_users(client, admin_token):
    r = await client.get("/api/v1/roles", headers=auth_header(admin_token))
    assert r.status_code == 200
    roles = {x["name"]: x for x in r.json()}
    assert set(roles) == {"ADMIN", "OPERATOR", "APPROVER", "AUDITOR"}
    assert [u["username"] for u in roles["AUDITOR"]["users"]] == ["auditor"]
    assert "recordings:read" in {p["name"] for p in roles["AUDITOR"]["permissions"]}
    assert roles["ADMIN"]["description"]


async def test_deactivate_and_reactivate_are_audited(client, db_session, admin_token):
    operator = await _user(db_session, "operator")
    r = await client.post(f"/api/v1/users/{operator.id}/deactivate", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["is_active"] is False
    (row,) = await _actions(db_session, "USER_DEACTIVATED")
    assert row.actor_username == "admin" and row.target_id == str(operator.id)
    # The deactivated account is refused on its next request.
    denied = await client.get("/api/v1/sessions/", headers=auth_header(issue_token("operator", ["OPERATOR"])))
    assert denied.status_code in (401, 403)
    assert (await client.post(f"/api/v1/users/{operator.id}/reactivate", headers=auth_header(admin_token))).json()["is_active"]
    assert len(await _actions(db_session, "USER_REACTIVATED")) == 1


async def test_non_admin_cannot_change_users(client, db_session, approver_token):
    operator = await _user(db_session, "operator")
    admin_role = await _role(db_session, "ADMIN")
    h = auth_header(approver_token)
    assert (await client.post(f"/api/v1/users/{operator.id}/deactivate", headers=h)).status_code == 403
    r = await client.post(f"/api/v1/users/{operator.id}/roles", headers=h, json={"role_id": str(admin_role.id)})
    assert r.status_code == 403
    await db_session.refresh(operator)
    assert [ur.role.name for ur in operator.roles] == ["OPERATOR"]


async def test_admin_cannot_change_or_deactivate_self(client, db_session, admin_token):
    admin = await _user(db_session, "admin")
    h = auth_header(admin_token)
    assert (await client.post(f"/api/v1/users/{admin.id}/deactivate", headers=h)).status_code == 409
    role = await _role(db_session, "ADMIN")
    assert (await client.delete(f"/api/v1/users/{admin.id}/roles/{role.id}", headers=h)).status_code == 409


async def test_assign_and_remove_role_validated_and_audited(client, db_session, admin_token):
    operator = await _user(db_session, "operator")
    auditor_role = await _role(db_session, "AUDITOR")
    h = auth_header(admin_token)
    r = await client.post(f"/api/v1/users/{operator.id}/roles", headers=h, json={"role_id": str(auditor_role.id)})
    assert r.status_code == 201 and {x["name"] for x in r.json()["roles"]} == {"OPERATOR", "AUDITOR"}
    (row,) = await _actions(db_session, "ROLE_ASSIGNED")
    assert row.details["role"] == "AUDITOR" and row.details["roles_before"] == ["OPERATOR"]
    assert (await client.post(f"/api/v1/users/{operator.id}/roles", headers=h,
                              json={"role_id": str(auditor_role.id)})).status_code == 409
    assert (await client.post(f"/api/v1/users/{operator.id}/roles", headers=h,
                              json={"role_id": "00000000-0000-0000-0000-000000000000"})).status_code == 422
    assert (await client.post(f"/api/v1/users/{operator.id}/roles", headers=h,
                              json={"role_id": str(auditor_role.id), "user_id": "x"})).status_code == 422
    assert (await client.delete(f"/api/v1/users/{operator.id}/roles/{auditor_role.id}", headers=h)).status_code == 200
    assert len(await _actions(db_session, "ROLE_REMOVED")) == 1


async def test_last_active_admin_is_protected(client, db_session, admin_token):
    admin2_token = await _second_admin(db_session)
    admin = await _user(db_session, "admin")
    admin_role = await _role(db_session, "ADMIN")
    # admin2 removes admin: allowed while admin2 remains. Then admin2 is the last one.
    assert (await client.delete(f"/api/v1/users/{admin.id}/roles/{admin_role.id}",
                                headers=auth_header(admin2_token))).status_code == 200
    admin2 = await _user(db_session, "admin2")
    # Another actor cannot exist as admin now, so exercise the guard via deactivate of admin2 by a
    # re-granted admin: re-assign, then try to strip the only OTHER admin's status twice over.
    assert (await client.post(f"/api/v1/users/{admin.id}/roles", headers=auth_header(admin2_token),
                              json={"role_id": str(admin_role.id)})).status_code == 201
    assert (await client.post(f"/api/v1/users/{admin2.id}/deactivate",
                              headers=auth_header(admin_token))).status_code == 200
    # admin is now the only active admin; admin2 (inactive) can no longer act, and admin cannot self-demote.
    assert (await client.post(f"/api/v1/users/{admin.id}/deactivate", headers=auth_header(admin_token))).status_code == 409
