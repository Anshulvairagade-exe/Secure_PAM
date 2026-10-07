"""
Asset management endpoints.

Assets are registered, admin-approved infrastructure targets. OPERATOR
may only ever READ this list — users cannot register or modify targets
themselves, matching "users cannot specify arbitrary targets" from the
Asset model's own docstring. Authorization is enforced here via
PermissionChecker (app/core/deps.py) against the real DB-backed RBAC
tables — never trust a frontend role.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.core.pagination import apply_sorting, paginate
from app.models.asset import Asset
from app.models.session import Session as SessionModel
from app.models.user import User
from app.schemas.assets import AssetCreate, AssetOut, AssetUpdate
from app.schemas.common import PaginatedResponse, PaginationParams

router = APIRouter(prefix="/assets", tags=["assets"])

_SORTABLE_COLUMNS = {
    "name", "hostname", "environment", "criticality", "asset_type",
    "created_at", "updated_at",
}
# Session states that mean "this asset is in active use right now" — see
# app/models/session.py's Status comment. A soft-deleted asset must not
# orphan a live session, so deletion is refused while any of these exist.
_ACTIVE_SESSION_STATUSES = ("CREATED", "STARTING", "ACTIVE", "TERMINATING")


async def _get_asset_or_404(db: AsyncSession, asset_id: UUID) -> Asset:
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.is_deleted == False)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        # Deliberately identical to "doesn't exist" for a soft-deleted row —
        # a non-admin should never learn a deleted asset ever existed.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


@router.get("", response_model=PaginatedResponse[AssetOut])
async def list_assets(
    pagination: PaginationParams = Depends(),
    environment: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    search: Optional[str] = Query(None, max_length=255, description="Matches name or hostname"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("assets", "read")),
):
    query = select(Asset).where(Asset.is_deleted == False)

    if environment:
        query = query.where(Asset.environment == environment)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if enabled is not None:
        query = query.where(Asset.enabled == enabled)
    if search:
        like = f"%{search}%"
        query = query.where(or_(Asset.name.ilike(like), Asset.hostname.ilike(like)))

    query = apply_sorting(query, Asset, pagination.sort_by, pagination.sort_order, _SORTABLE_COLUMNS)
    return await paginate(db, query, pagination, schema=AssetOut)


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("assets", "create")),
):
    asset = Asset(**body.model_dump(), created_by=current_user.id, updated_by=current_user.id)
    db.add(asset)
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="ASSET_CREATED",
        target_type="asset",
        target_id=str(asset.id),
        source_ip=client_ip(request),
        metadata={"name": asset.name, "asset_type": asset.asset_type},
    )
    await db.commit()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("assets", "read")),
):
    return await _get_asset_or_404(db, asset_id)


@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: UUID,
    body: AssetUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("assets", "update")),
):
    asset = await _get_asset_or_404(db, asset_id)

    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(asset, field, value)
    asset.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="ASSET_UPDATED",
        target_type="asset",
        target_id=str(asset.id),
        source_ip=client_ip(request),
        metadata={"changed_fields": sorted(changes.keys())},
    )
    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("assets", "delete")),
):
    asset = await _get_asset_or_404(db, asset_id)

    active_sessions = await db.scalar(
        select(func.count()).select_from(SessionModel).where(
            SessionModel.asset_id == asset.id,
            SessionModel.status.in_(_ACTIVE_SESSION_STATUSES),
        )
    )
    if active_sessions:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot delete this asset: {active_sessions} active session(s) still reference it.",
        )

    # Soft delete — never hard-delete a registered target (audit history,
    # and any past Session/AccessRequest/Recording rows, must stay valid).
    asset.is_deleted = True
    asset.enabled = False
    asset.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="ASSET_DELETED",
        target_type="asset",
        target_id=str(asset.id),
        source_ip=client_ip(request),
        metadata={"name": asset.name},
    )
    await db.commit()
