"""
Approval workflow at the HTTP level: approve, reject, self-approval
prevention, duplicate-decision prevention, unauthorized approval, and
RBAC on the approval queue itself.

Every test here uses a policy with require_approval=True, auto_approve=False
assigned to the target asset — this guarantees the created request lands
in APPROVAL_REQUIRED regardless of real-world business-hours/risk wobble
(see test_access_requests.py's module docstring for why that matters).
"""

from uuid import uuid4
from datetime import datetime, timedelta, timezone

from app.models.access_request import AccessRequest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from tests.conftest import auth_header


async def _create_approval_required_request(client: AsyncClient, admin_token: str, operator_token: str, db_session: AsyncSession) -> tuple[str, str]:
    """Returns (access_request_id, approval_id)."""
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    policy_resp = await client.post(
        "/api/v1/policies",
        json={"name": f"ForceApproval-{uuid4()}", "require_approval": True, "auto_approve": False},
        headers=auth_header(admin_token),
    )
    policy_id = policy_resp.json()["id"]
    await client.patch(
        f"/api/v1/assets/{asset.id}", json={"policy_id": policy_id}, headers=auth_header(admin_token)
    )

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "needs approval", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    assert create.status_code == 201
    request_body = create.json()
    assert request_body["status"] == "APPROVAL_REQUIRED"
    request_id = request_body["id"]

    approvals = await client.get(
        "/api/v1/approvals", params={"status": "PENDING", "page_size": 50}, headers=auth_header(admin_token)
    )
    approval_id = next(a["id"] for a in approvals.json()["items"] if a["request_id"] == request_id)
    return request_id, approval_id


async def test_approver_can_approve(client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession):
    request_id, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)

    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/approve", json={"comment": "approved"}, headers=auth_header(approver_token)
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "APPROVED"

    req = await client.get(f"/api/v1/access-requests/{request_id}", headers=auth_header(admin_token))
    assert req.json()["status"] == "ACTIVE"  # JIT grant created, request went live
    assert req.json()["decided_by"] is not None


async def test_unauthorized_user_cannot_approve(client: AsyncClient, admin_token: str, operator_token: str, db_session: AsyncSession):
    """OPERATOR has no approvals:approve permission."""
    _, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)

    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(operator_token)
    )
    assert resp.status_code == 403


async def test_requester_cannot_self_approve(client: AsyncClient, admin_token: str, db_session: AsyncSession):
    """Make the ADMIN account itself the requester, then try to approve its
    own request with an admin_token — ADMIN also holds approvals:approve,
    so this isolates the self-approval check from a permission check."""
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    policy_resp = await client.post(
        "/api/v1/policies",
        json={"name": f"ForceApproval-{uuid4()}", "require_approval": True, "auto_approve": False},
        headers=auth_header(admin_token),
    )
    await client.patch(
        f"/api/v1/assets/{asset.id}", json={"policy_id": policy_resp.json()["id"]}, headers=auth_header(admin_token)
    )

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "self approval attempt", "requested_duration": 15},
        headers=auth_header(admin_token),
    )
    request_id = create.json()["id"]

    approvals = await client.get(
        "/api/v1/approvals", params={"status": "PENDING", "page_size": 50}, headers=auth_header(admin_token)
    )
    approval_id = next(a["id"] for a in approvals.json()["items"] if a["request_id"] == request_id)

    resp = await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(admin_token))
    assert resp.status_code == 403


async def test_duplicate_approval_is_rejected(client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession):
    _, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)

    first = await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(approver_token))
    assert first.status_code == 200

    second = await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(approver_token))
    assert second.status_code == 409


async def test_rejecting_an_already_approved_request_is_invalid_transition(
    client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession
):
    _, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)
    await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(approver_token))

    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reject", json={"comment": "too late"}, headers=auth_header(approver_token)
    )
    assert resp.status_code == 409


async def test_reject_requires_a_comment(client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession):
    _, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)

    resp = await client.post(f"/api/v1/approvals/{approval_id}/reject", json={}, headers=auth_header(approver_token))
    assert resp.status_code == 422


async def test_approver_can_reject_with_comment(client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession):
    request_id, approval_id = await _create_approval_required_request(client, admin_token, operator_token, db_session)

    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reject", json={"comment": "not justified"}, headers=auth_header(approver_token)
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "REJECTED"

    req = await client.get(f"/api/v1/access-requests/{request_id}", headers=auth_header(admin_token))
    assert req.json()["status"] == "REJECTED"


async def test_jit_grant_duration_is_clamped_to_policy_maximum_on_approval(
    client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession
):
    """The spec's own example: requested 120 minutes, policy maximum 30 ->
    actual JIT grant is 30 minutes, never the client's requested value."""
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    policy_resp = await client.post(
        "/api/v1/policies",
        json={
            "name": f"ClampTest-{uuid4()}", "require_approval": True, "auto_approve": False,
            "max_session_duration": 30,
        },
        headers=auth_header(admin_token),
    )
    await client.patch(
        f"/api/v1/assets/{asset.id}", json={"policy_id": policy_resp.json()["id"]}, headers=auth_header(admin_token)
    )

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "long request", "requested_duration": 120},
        headers=auth_header(operator_token),
    )
    assert create.status_code == 201
    request_id = create.json()["id"]
    assert create.json()["requested_duration"] == 120  # the REQUEST remembers what was asked for

    approvals = await client.get(
        "/api/v1/approvals", params={"status": "PENDING", "page_size": 50}, headers=auth_header(admin_token)
    )
    approval_id = next(a["id"] for a in approvals.json()["items"] if a["request_id"] == request_id)
    approve = await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(approver_token))
    assert approve.status_code == 200

    jit_result = await db_session.execute(select(JITGrant).where(JITGrant.request_id == request_id))
    grant = jit_result.scalar_one()
    actual_minutes = (grant.expires_at - grant.granted_at).total_seconds() / 60
    assert abs(actual_minutes - 30) < 1  # clamped to the policy maximum, not 120


async def test_operator_cannot_view_approval_queue(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/approvals", headers=auth_header(operator_token))
    assert resp.status_code == 403


async def test_auditor_can_view_approval_queue(client: AsyncClient, auditor_token: str):
    resp = await client.get("/api/v1/approvals", headers=auth_header(auditor_token))
    assert resp.status_code == 200


async def test_expired_request_cannot_be_approved(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
    approver_token: str,
    db_session: AsyncSession,
):
    request_id, approval_id = await _create_approval_required_request(
        client, admin_token, operator_token, db_session
    )

    request = await db_session.get(AccessRequest, request_id)
    assert request is not None
    request.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={},
        headers=auth_header(approver_token),
    )

    assert response.status_code == 409

    await db_session.refresh(request)
    assert request.status == "APPROVAL_REQUIRED"


async def test_expired_request_cannot_be_rejected(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
    approver_token: str,
    db_session: AsyncSession,
):
    request_id, approval_id = await _create_approval_required_request(
        client, admin_token, operator_token, db_session
    )

    request = await db_session.get(AccessRequest, request_id)
    assert request is not None
    request.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/approvals/{approval_id}/reject",
        json={"comment": "Testing expired request"},
        headers=auth_header(approver_token),
    )

    assert response.status_code == 409

    await db_session.refresh(request)
    assert request.status == "APPROVAL_REQUIRED"
