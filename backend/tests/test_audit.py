"""
Audit logging: successful administrative actions and permission denials
both produce a persisted AuditLog row, and that row's metadata never
contains more than the safe, intentional fields we chose to record.
"""

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from tests.conftest import auth_header


async def _latest_audit_event(db_session: AsyncSession, action: str) -> AuditLog:
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.timestamp.desc())
    )
    event = result.scalars().first()
    assert event is not None, f"no AuditLog row found for action={action!r}"
    return event


async def test_successful_asset_creation_generates_audit_event(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    resp = await client.post(
        "/api/v1/assets",
        json={
            "name": "AUDIT-TEST-ASSET",
            "hostname": "audit-test.internal",
            "ip_address": "10.0.9.5",
            "port": 22,
            "protocol": "SSH",
            "asset_type": "LINUX_SERVER",
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201
    asset_id = resp.json()["id"]

    event = await _latest_audit_event(db_session, "ASSET_CREATED")
    assert event.actor_username == "admin"
    assert event.target_id == asset_id
    assert event.result == "SUCCESS"


async def test_asset_update_and_delete_generate_audit_events(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    create = await client.post(
        "/api/v1/assets",
        json={
            "name": "AUDIT-UPDATE-ASSET",
            "hostname": "audit-update.internal",
            "ip_address": "10.0.9.6",
            "port": 22,
            "protocol": "SSH",
            "asset_type": "LINUX_SERVER",
        },
        headers=auth_header(admin_token),
    )
    asset_id = create.json()["id"]

    await client.patch(
        f"/api/v1/assets/{asset_id}", json={"criticality": "HIGH"}, headers=auth_header(admin_token)
    )
    update_event = await _latest_audit_event(db_session, "ASSET_UPDATED")
    assert update_event.target_id == asset_id
    assert update_event.details == {"changed_fields": ["criticality"]}

    await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_header(admin_token))
    delete_event = await _latest_audit_event(db_session, "ASSET_DELETED")
    assert delete_event.target_id == asset_id


async def test_denied_action_generates_access_denied_audit_event(
    client: AsyncClient, operator_token: str, db_session: AsyncSession
):
    resp = await client.post(
        "/api/v1/assets",
        json={
            "name": "SHOULD-BE-DENIED",
            "hostname": "x.internal",
            "ip_address": "10.0.0.1",
            "port": 22,
            "protocol": "SSH",
            "asset_type": "OTHER",
        },
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 403

    event = await _latest_audit_event(db_session, "ACCESS_DENIED")
    assert event.actor_username == "operator"
    assert event.result == "DENIED"
    assert event.target_type == "assets"
    assert event.details == {"required_permission": "assets:create"}


async def test_application_creation_generates_audit_event(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    resp = await client.post(
        "/api/v1/applications",
        json={"name": "AUDIT-TEST-APP", "hostname": "audit-app.internal", "port": 443, "protocol": "HTTPS"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201

    event = await _latest_audit_event(db_session, "APPLICATION_CREATED")
    assert event.target_id == resp.json()["id"]


async def test_policy_creation_generates_audit_event(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    resp = await client.post(
        "/api/v1/policies", json={"name": "Audit Test Policy"}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 201

    event = await _latest_audit_event(db_session, "POLICY_CREATED")
    assert event.target_id == resp.json()["id"]


async def test_audit_metadata_never_contains_unexpected_keys(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    """
    Guards against accidentally widening what gets written to audit
    metadata in the future (e.g. dumping the full request body, which
    could one day include something sensitive) — only the explicit,
    reviewed keys from app/api/v1/assets.py's write_audit_log calls
    should ever appear.
    """
    resp = await client.post(
        "/api/v1/assets",
        json={
            "name": "AUDIT-METADATA-CHECK",
            "hostname": "meta-check.internal",
            "ip_address": "10.0.9.7",
            "port": 22,
            "protocol": "SSH",
            "asset_type": "LINUX_SERVER",
            "owner": "Some Team",
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201

    event = await _latest_audit_event(db_session, "ASSET_CREATED")
    assert set(event.details.keys()) == {"name", "asset_type"}
    assert "owner" not in event.details
    assert "ip_address" not in event.details
