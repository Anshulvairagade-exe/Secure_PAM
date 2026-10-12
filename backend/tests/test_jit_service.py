"""
JITService: grant correctness (including the policy-maximum clamp),
validate/revoke/expire, and unauthorized/expired validation. JITService
itself is the authority future gateways will call — these tests exercise
it directly, the same way test_rbac.py exercises PermissionChecker
directly, since there is no dedicated JIT REST endpoint (by design — see
JITService's module docstring: it's a service for future gateway code,
not an API surface Phase 4 was asked to add).
"""
import pytest

from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_request_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.user import User
from app.services.jit_service import JITService

service = JITService()


async def _get(db_session: AsyncSession, model, **filters):
    conditions = [getattr(model, k) == v for k, v in filters.items()]
    result = await db_session.execute(select(model).where(*conditions))
    return result.scalar_one()


async def _make_request(db_session: AsyncSession, *, user_id, asset_id, protocol="SSH") -> AccessRequest:
    """jit_grants.request_id is a real foreign key to access_requests.id —
    a JIT grant always has one real originating request, so tests need an
    actual row here, not a random uuid4()."""
    req = AccessRequest(
        request_number=generate_request_number(), user_id=user_id, asset_id=asset_id,
        protocol=protocol, reason="jit service test fixture", requested_duration=30,
        status="ACTIVE", approval_required=False, jit_required=True, mfa_required=False,
        recording_required=False,
    )
    db_session.add(req)
    await db_session.flush()
    return req


async def test_grant_computes_expiry_from_duration(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)

    grant = await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    assert grant.status == "ACTIVE"
    delta = grant.expires_at - grant.granted_at
    assert abs(delta.total_seconds() - 30 * 60) < 2  # allow for test execution jitter


async def test_validate_succeeds_for_active_grant(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    grant = await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    result = await service.validate(db_session, user_id=operator.id, target_id=asset.id, protocol="SSH")
    assert result is not None
    assert result.id == grant.id


async def test_validate_denies_wrong_protocol(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    result = await service.validate(db_session, user_id=operator.id, target_id=asset.id, protocol="RDP")
    assert result is None


async def test_validate_denies_wrong_user(db_session: AsyncSession):
    """Unauthorized JIT validation — grant belongs to `operator`, not `admin`."""
    operator = await _get(db_session, User, username="operator")
    admin = await _get(db_session, User, username="admin")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    result = await service.validate(db_session, user_id=admin.id, target_id=asset.id, protocol="SSH")
    assert result is None


async def test_validate_denies_wrong_target(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    other_asset = await _get(db_session, Asset, name="WIN-PROD-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    result = await service.validate(db_session, user_id=operator.id, target_id=other_asset.id, protocol="SSH")
    assert result is None


async def test_expired_grant_is_denied_and_lazily_marked_expired(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    grant = JITGrant(
        request_id=req.id, user_id=operator.id, asset_id=asset.id, protocol="SSH",
        granted_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        status="ACTIVE",
    )
    db_session.add(grant)
    await db_session.commit()

    result = await service.validate(db_session, user_id=operator.id, target_id=asset.id, protocol="SSH")
    assert result is None

    await db_session.refresh(grant)
    assert grant.status == "EXPIRED"


async def test_revoke_immediately_invalidates_an_active_grant(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    grant = await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    await db_session.commit()

    await service.revoke(db_session, grant)
    await db_session.commit()

    assert grant.status == "REVOKED"
    assert grant.revoked_at is not None

    result = await service.validate(db_session, user_id=operator.id, target_id=asset.id, protocol="SSH")
    assert result is None


async def test_is_active_reflects_status_and_expiry_without_db_access(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(db_session, user_id=operator.id, asset_id=asset.id)
    grant = await service.grant(
        db_session, request_id=req.id, user_id=operator.id, asset_id=asset.id, application_id=None,
        protocol="SSH", duration_minutes=30, created_by=None,
    )
    assert service.is_active(grant) is True

    grant.status = "REVOKED"
    assert service.is_active(grant) is False


@pytest.mark.parametrize("duration_minutes", [0, -1])
async def test_grant_rejects_non_positive_duration(
    db_session: AsyncSession,
    duration_minutes: int,
):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(
        db_session, user_id=operator.id, asset_id=asset.id
    )

    with pytest.raises(ValueError, match="greater than zero"):
        await service.grant(
            db_session,
            request_id=req.id,
            user_id=operator.id,
            asset_id=asset.id,
            application_id=None,
            protocol="SSH",
            duration_minutes=duration_minutes,
            created_by=None,
        )


async def test_grant_duration_never_exceeds_request_duration(
    db_session: AsyncSession,
):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(
        db_session, user_id=operator.id, asset_id=asset.id
    )

    # The request asks for 30 minutes, but the caller supplies 60.
    grant = await service.grant(
        db_session,
        request_id=req.id,
        user_id=operator.id,
        asset_id=asset.id,
        application_id=None,
        protocol="SSH",
        duration_minutes=60,
        created_by=None,
    )

    actual_minutes = (
        grant.expires_at - grant.granted_at
    ).total_seconds() / 60
    assert abs(actual_minutes - 30) < 1


async def test_grant_duration_respects_policy_maximum(
    db_session: AsyncSession,
):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    req = await _make_request(
        db_session, user_id=operator.id, asset_id=asset.id
    )
    req.policy_decision = {"max_duration": 10}
    await db_session.flush()

    grant = await service.grant(
        db_session,
        request_id=req.id,
        user_id=operator.id,
        asset_id=asset.id,
        application_id=None,
        protocol="SSH",
        duration_minutes=30,
        created_by=None,
    )

    actual_minutes = (
        grant.expires_at - grant.granted_at
    ).total_seconds() / 60
    assert abs(actual_minutes - 10) < 1


async def test_grant_rejects_target_mismatch(
    db_session: AsyncSession,
):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    other_asset = await _get(db_session, Asset, name="WIN-PROD-01")

    req = await _make_request(
        db_session, user_id=operator.id, asset_id=asset.id
    )

    with pytest.raises(ValueError, match="match the originating access request"):
        await service.grant(
            db_session,
            request_id=req.id,
            user_id=operator.id,
            asset_id=other_asset.id,
            application_id=None,
            protocol="SSH",
            duration_minutes=15,
            created_by=None,
        )
