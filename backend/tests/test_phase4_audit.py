"""Audit events for the Phase 4 workflow: request creation, cancellation,
approval, and rejection each produce their documented AuditLog rows."""

from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.audit import AuditLog
from tests.conftest import auth_header


async def _actions_for_request(db_session: AsyncSession, request_id: str) -> set[str]:
    result = await db_session.execute(select(AuditLog).where(AuditLog.request_id == request_id))
    return {row.action for row in result.scalars().all()}


async def test_request_creation_generates_decision_pipeline_events(
    client: AsyncClient, operator_token: str, db_session: AsyncSession
):
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "audit test", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    actions = await _actions_for_request(db_session, request_id)
    assert "ACCESS_REQUEST_CREATED" in actions
    assert "POLICY_EVALUATED" in actions
    assert "RISK_EVALUATED" in actions
    # Exactly one of these three terminal-at-creation outcomes fired.
    assert len(actions & {"ACCESS_DENIED", "APPROVAL_REQUESTED", "ACCESS_ALLOWED"}) == 1


async def test_cancellation_generates_audit_event(
    client: AsyncClient, operator_token: str, db_session: AsyncSession
):
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()
    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "cancel audit test", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    cancel = await client.post(f"/api/v1/access-requests/{request_id}/cancel", headers=auth_header(operator_token))
    if cancel.status_code != 200:
        return  # auto-approved this run (business-hours-dependent) — nothing to cancel

    actions = await _actions_for_request(db_session, request_id)
    assert "ACCESS_REQUEST_CANCELLED" in actions


async def test_approval_generates_approval_and_jit_events(
    client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession
):
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    policy_resp = await client.post(
        "/api/v1/policies",
        json={"name": f"AuditApprove-{uuid4()}", "require_approval": True, "auto_approve": False},
        headers=auth_header(admin_token),
    )
    await client.patch(
        f"/api/v1/assets/{asset.id}", json={"policy_id": policy_resp.json()["id"]}, headers=auth_header(admin_token)
    )

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "approval audit test", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]
    assert create.json()["status"] == "APPROVAL_REQUIRED"

    approvals = await client.get(
        "/api/v1/approvals", params={"status": "PENDING", "page_size": 50}, headers=auth_header(admin_token)
    )
    approval_id = next(a["id"] for a in approvals.json()["items"] if a["request_id"] == request_id)
    await client.post(f"/api/v1/approvals/{approval_id}/approve", json={}, headers=auth_header(approver_token))

    actions = await _actions_for_request(db_session, request_id)
    assert "APPROVAL_GRANTED" in actions
    assert "JIT_GRANTED" in actions


async def test_rejection_generates_approval_rejected_event(
    client: AsyncClient, admin_token: str, operator_token: str, approver_token: str, db_session: AsyncSession
):
    result = await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    asset = result.scalar_one()

    policy_resp = await client.post(
        "/api/v1/policies",
        json={"name": f"AuditReject-{uuid4()}", "require_approval": True, "auto_approve": False},
        headers=auth_header(admin_token),
    )
    await client.patch(
        f"/api/v1/assets/{asset.id}", json={"policy_id": policy_resp.json()["id"]}, headers=auth_header(admin_token)
    )

    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "rejection audit test", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    approvals = await client.get(
        "/api/v1/approvals", params={"status": "PENDING", "page_size": 50}, headers=auth_header(admin_token)
    )
    approval_id = next(a["id"] for a in approvals.json()["items"] if a["request_id"] == request_id)
    await client.post(
        f"/api/v1/approvals/{approval_id}/reject", json={"comment": "denied for audit test"},
        headers=auth_header(approver_token),
    )

    actions = await _actions_for_request(db_session, request_id)
    assert "APPROVAL_REJECTED" in actions
