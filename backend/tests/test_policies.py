"""Policy CRUD + RBAC + validation."""

from httpx import AsyncClient

from tests.conftest import auth_header


async def test_list_policies_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/policies")
    assert resp.status_code == 401


async def test_operator_cannot_read_policies(client: AsyncClient, operator_token: str):
    """Per spec: OPERATOR reads assets/applications but not policies."""
    resp = await client.get("/api/v1/policies", headers=auth_header(operator_token))
    assert resp.status_code == 403


async def test_approver_can_read_policies(client: AsyncClient, approver_token: str):
    resp = await client.get("/api/v1/policies", headers=auth_header(approver_token))
    assert resp.status_code == 200


async def test_auditor_can_read_policies(client: AsyncClient, auditor_token: str):
    resp = await client.get("/api/v1/policies", headers=auth_header(auditor_token))
    assert resp.status_code == 200
    # Seed data creates exactly 4 policies.
    assert resp.json()["total"] == 4


async def test_admin_can_create_policy(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/policies",
        json={
            "name": "Test Policy",
            "risk_threshold": "MEDIUM",
            "allowed_roles": ["OPERATOR", "APPROVER"],
            "allowed_protocols": ["SSH", "RDP"],
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["allowed_roles"] == ["OPERATOR", "APPROVER"]
    assert body["created_by"] is not None


async def test_approver_cannot_create_policy(client: AsyncClient, approver_token: str):
    resp = await client.post(
        "/api/v1/policies", json={"name": "Approver Try"}, headers=auth_header(approver_token)
    )
    assert resp.status_code == 403


async def test_auditor_cannot_create_policy(client: AsyncClient, auditor_token: str):
    resp = await client.post(
        "/api/v1/policies", json={"name": "Auditor Try"}, headers=auth_header(auditor_token)
    )
    assert resp.status_code == 403


async def test_duplicate_policy_name_returns_409(client: AsyncClient, admin_token: str):
    await client.post("/api/v1/policies", json={"name": "Dup Policy"}, headers=auth_header(admin_token))
    resp = await client.post("/api/v1/policies", json={"name": "Dup Policy"}, headers=auth_header(admin_token))
    assert resp.status_code == 409


async def test_invalid_risk_threshold_returns_422(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Bad Risk", "risk_threshold": "SUPER_HIGH"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_invalid_max_session_duration_returns_422(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Bad Duration", "max_session_duration": 9999},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_invalid_allowed_role_entry_returns_422(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Bad Role List", "allowed_roles": ["SUPERUSER"]},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_get_nonexistent_policy_returns_404(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/policies/00000000-0000-0000-0000-000000000000", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


async def test_admin_can_update_policy(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/policies", json={"name": "Update Policy"}, headers=auth_header(admin_token)
    )
    policy_id = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/policies/{policy_id}", json={"require_mfa": False}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 200
    assert resp.json()["require_mfa"] is False


async def test_admin_can_delete_policy(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/policies", json={"name": "Delete Policy"}, headers=auth_header(admin_token)
    )
    policy_id = create.json()["id"]

    delete = await client.delete(f"/api/v1/policies/{policy_id}", headers=auth_header(admin_token))
    assert delete.status_code == 204

    get_after = await client.get(f"/api/v1/policies/{policy_id}", headers=auth_header(admin_token))
    assert get_after.status_code == 404
