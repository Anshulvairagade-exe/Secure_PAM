"""
Policy management endpoints.

Policies are pure data — no decision logic lives in the frontend or here.
The future Risk/Policy Engine (Phase 4) reads these rows to decide
approval/MFA/recording/JIT requirements for a given access request; this
module only owns CRUD + validation.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.core.pagination import apply_sorting, paginate
from app.models.policy import Policy
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.policies import PolicyCreate, PolicyOut, PolicyUpdate

router = APIRouter(prefix="/policies", tags=["policies"])

_SORTABLE_COLUMNS = {"name", "risk_threshold", "created_at", "updated_at"}


async def _get_policy_or_404(db: AsyncSession, policy_id: UUID) -> Policy:
    result = await db.execute(select(Policy).where(Policy.id == policy_id, Policy.is_deleted == False))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    return policy


@router.get("", response_model=PaginatedResponse[PolicyOut])
async def list_policies(
    pagination: PaginationParams = Depends(),
    enabled: Optional[bool] = Query(None),
    risk_threshold: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("policies", "read")),
):
    query = select(Policy).where(Policy.is_deleted == False)

    if enabled is not None:
        query = query.where(Policy.enabled == enabled)
    if risk_threshold:
        query = query.where(Policy.risk_threshold == risk_threshold)

    query = apply_sorting(query, Policy, pagination.sort_by, pagination.sort_order, _SORTABLE_COLUMNS)
    return await paginate(db, query, pagination, schema=PolicyOut)


@router.post("", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("policies", "create")),
):
    existing = await db.execute(select(Policy).where(Policy.name == body.name, Policy.is_deleted == False))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, f"A policy named '{body.name}' already exists.")

    policy = Policy(**body.model_dump(), created_by=current_user.id, updated_by=current_user.id)
    db.add(policy)
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="POLICY_CREATED",
        target_type="policy",
        target_id=str(policy.id),
        source_ip=client_ip(request),
        metadata={"name": policy.name, "risk_threshold": policy.risk_threshold},
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(
    policy_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("policies", "read")),
):
    return await _get_policy_or_404(db, policy_id)


@router.patch("/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: UUID,
    body: PolicyUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("policies", "update")),
):
    policy = await _get_policy_or_404(db, policy_id)

    changes = body.model_dump(exclude_unset=True)

    if "name" in changes and changes["name"] != policy.name:
        existing = await db.execute(
            select(Policy).where(Policy.name == changes["name"], Policy.is_deleted == False)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status.HTTP_409_CONFLICT, f"A policy named '{changes['name']}' already exists.")

    for field, value in changes.items():
        setattr(policy, field, value)
    policy.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="POLICY_UPDATED",
        target_type="policy",
        target_id=str(policy.id),
        source_ip=client_ip(request),
        metadata={"changed_fields": sorted(changes.keys())},
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("policies", "delete")),
):
    policy = await _get_policy_or_404(db, policy_id)

    # Soft delete only. Any Asset/Application still pointing at this policy
    # keeps working — policy_id is ON DELETE SET NULL at the DB level, and
    # is_deleted means "no longer assignable", not "never existed".
    policy.is_deleted = True
    policy.enabled = False
    policy.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="POLICY_DELETED",
        target_type="policy",
        target_id=str(policy.id),
        source_ip=client_ip(request),
        metadata={"name": policy.name},
    )
    await db.commit()
