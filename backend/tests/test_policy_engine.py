"""
Policy evaluator: role/protocol/environment/asset-type restrictions,
business-hours and allowed-days, duration clamping, explicit deny, and
the fail-safe default stance (no policy assigned / policy disabled).

Policy instances here are constructed in-memory (never added to the
session) — PolicyEvaluator.evaluate_access() is a pure function over
already-loaded rows, so no DB round-trip is needed to exercise it.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.policy import Policy
from app.models.user import User
from app.policies.evaluator import DEFAULT_MAX_DURATION_MINUTES, PolicyEvaluator

BUSINESS_HOURS_NOW = datetime(2025, 1, 8, 12, 0, tzinfo=timezone.utc)  # Wed noon UTC
OFF_HOURS_NOW = datetime(2025, 1, 11, 12, 0, tzinfo=timezone.utc)  # Sat noon UTC

evaluator = PolicyEvaluator()


def _permissive_policy(**overrides) -> Policy:
    defaults = dict(
        id=uuid.uuid4(),  # never flushed — SQLAlchemy only applies Python-side
        # defaults (incl. UUIDMixin's) at flush time, so a transient instance
        # needs this set explicitly to behave like a real fetched-from-DB row.
        name="Test Policy", enabled=True, risk_threshold="LOW", min_risk_score=0,
        require_approval=False, jit_required=True, require_mfa=False, require_recording=False,
        max_session_duration=60, download_allowed=True, upload_allowed=True, clipboard_allowed=True,
        auto_approve=True, deny_access=False, business_hours_only=False,
        allowed_roles=None, allowed_asset_types=None, allowed_environments=None,
        allowed_protocols=None, allowed_days=None,
    )
    defaults.update(overrides)
    return Policy(**defaults)


async def _get(db_session: AsyncSession, model, **filters):
    conditions = [getattr(model, k) == v for k, v in filters.items()]
    result = await db_session.execute(select(model).where(*conditions))
    return result.scalar_one()


async def test_role_allowed(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(allowed_roles=["OPERATOR", "APPROVER"])

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True


async def test_role_denied(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(allowed_roles=["ADMIN"])

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False
    assert any("role" in r.lower() for r in decision.reasons)


async def test_protocol_allowed(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(allowed_protocols=["SSH", "RDP"])

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True


async def test_protocol_denied(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(allowed_protocols=["RDP"])

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False


async def test_environment_restriction(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    prod_asset = await _get(db_session, Asset, name="WIN-PROD-01")
    policy = _permissive_policy(allowed_environments=["DEVELOPMENT"])

    decision = evaluator.evaluate_access(
        user=operator, target=prod_asset, policy=policy, protocol="RDP", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False
    assert any("environment" in r.lower() for r in decision.reasons)


async def test_asset_type_restriction(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    win_asset = await _get(db_session, Asset, name="WIN-DEV-01")  # WINDOWS_WORKSTATION
    policy = _permissive_policy(allowed_asset_types=["LINUX_SERVER"])

    decision = evaluator.evaluate_access(
        user=operator, target=win_asset, policy=policy, protocol="RDP", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False


async def test_max_duration_is_clamped_not_rejected(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(max_session_duration=30)

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=120, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True  # clamped, not rejected
    assert decision.max_duration == 30


async def test_business_hours_restriction(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(business_hours_only=True)

    in_hours = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    off_hours = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=OFF_HOURS_NOW,
    )
    assert in_hours.allowed is True
    assert off_hours.allowed is False


async def test_allowed_days_restriction(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    # BUSINESS_HOURS_NOW is a Wednesday.
    policy = _permissive_policy(allowed_days=["MON", "TUE"])

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False


async def test_explicit_deny_access(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(deny_access=True)

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is False
    assert any("explicitly denies" in r for r in decision.reasons)


async def test_disabled_policy_falls_back_to_default(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(enabled=False)

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=120, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True  # fail-safe: still allowed, but conservative
    assert decision.approval_required is True
    assert decision.mfa_required is True
    assert decision.auto_approve is False
    assert decision.policy_id is None
    assert decision.max_duration == DEFAULT_MAX_DURATION_MINUTES


async def test_no_policy_assigned_falls_back_to_default(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=None, protocol="SSH", requested_duration=120, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.policy_id is None
    assert "No policy is assigned" in decision.reasons[0]


async def test_enabled_permissive_policy_grants_controls_from_policy(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = _permissive_policy(require_mfa=True, require_recording=True, jit_required=False)

    decision = evaluator.evaluate_access(
        user=operator, target=asset, policy=policy, protocol="SSH", requested_duration=30, now=BUSINESS_HOURS_NOW,
    )
    assert decision.allowed is True
    assert decision.mfa_required is True
    assert decision.recording_required is True
    assert decision.jit_required is False
    assert decision.policy_id == policy.id
