"""
RBAC foundation: RoleChecker / PermissionChecker dependency behavior.

NOTE ON SCOPE: as of Phase 2, no HTTP endpoint actually applies
RoleChecker/PermissionChecker yet (Assets/Policies/etc. CRUD — the first
real role-gated routes — lands in a later phase). These tests exercise the
dependency classes directly against real User rows loaded from the DB, so
the RBAC mechanism itself is proven correct ahead of any route using it.
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import PermissionChecker, RoleChecker
from app.models.user import User


async def _get_user(db_session: AsyncSession, username: str) -> User:
    result = await db_session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    assert user is not None, f"seed user {username!r} missing"
    return user


async def test_role_checker_allows_matching_role(db_session: AsyncSession):
    admin = await _get_user(db_session, "admin")
    checker = RoleChecker(["ADMIN"])
    result = await checker(current_user=admin)
    assert result is admin


async def test_role_checker_rejects_non_matching_role(db_session: AsyncSession):
    operator = await _get_user(db_session, "operator")
    checker = RoleChecker(["ADMIN", "APPROVER"])
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=operator)
    assert exc_info.value.status_code == 403


async def test_permission_checker_allows_held_permission(db_session: AsyncSession):
    approver = await _get_user(db_session, "approver")
    checker = PermissionChecker("approvals", "approve")
    result = await checker(current_user=approver)
    assert result is approver


async def test_permission_checker_rejects_missing_permission(db_session: AsyncSession):
    operator = await _get_user(db_session, "operator")
    # Operators can create access requests but cannot approve them.
    checker = PermissionChecker("approvals", "approve")
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=operator)
    assert exc_info.value.status_code == 403


async def test_admin_bypasses_explicit_permission_grants(db_session: AsyncSession):
    """ADMIN is granted every permission at seed time (see app/main.py), so
    this also covers the explicit 'ADMIN has all permissions' short-circuit
    in PermissionChecker."""
    admin = await _get_user(db_session, "admin")
    checker = PermissionChecker("vault", "manage")
    result = await checker(current_user=admin)
    assert result is admin


async def test_auditor_cannot_approve(db_session: AsyncSession):
    auditor = await _get_user(db_session, "auditor")
    checker = PermissionChecker("approvals", "approve")
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=auditor)
    assert exc_info.value.status_code == 403
