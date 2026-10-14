"""
Access Request endpoints.

The entire decision workflow (policy evaluation, risk evaluation, the
decision matrix, persistence, audit) lives in
app/services/access_decision.py — this module only translates HTTP in
and out of that service and enforces who may see/do what.

IDOR prevention: a requester without access_requests:read (view-all) can
only ever see their OWN requests — list is silently filtered, and detail/
cancel on someone else's request returns 404 (not 403), so a non-owner
can't even confirm the request exists. See _get_visible_request_or_404.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import get_current_active_user, get_db
from app.core.pagination import apply_sorting, paginate
from app.models.access_request import AccessRequest
from app.models.jit_grant import JITGrant
from app.models.user import User
from app.schemas.access_requests import (
    AccessRequestCreate,
    AccessRequestDetailOut,
    AccessRequestOut,
    JITGrantSummary,
)
from app.schemas.common import PaginatedResponse, PaginationParams
from app.services.access_decision import (
    AccessDecisionService,
    InvalidTargetError,
    InvalidTransitionError,
)

router = APIRouter(prefix="/access-requests", tags=["access-requests"])

_SORTABLE_COLUMNS = {"created_at", "status", "risk_score", "expires_at"}
_service = AccessDecisionService()


def _permission_names(user: User) -> set[str]:
    perms: set[str] = set()
    for ur in user.roles:
        if ur.role and ur.role.is_active:
            for perm in ur.role.permissions:
                perms.add(f"{perm.resource}:{perm.action}")
    return perms


def _role_names(user: User) -> set[str]:
    return {
        ur.role.name
        for ur in user.roles
        if ur.role and ur.role.is_active
    }


def _can_view_all(user: User) -> bool:
    return "ADMIN" in _role_names(user) or "access_requests:read" in _permission_names(user)


def _can_view_own(user: User) -> bool:
    return "access_requests:read_own" in _permission_names(user)


async def _get_visible_request_or_404(db: AsyncSession, request_id: UUID, user: User) -> AccessRequest:
    result = await db.execute(select(AccessRequest).where(AccessRequest.id == request_id))
    access_request = result.scalar_one_or_none()
    if access_request is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")

    if not _can_view_all(user) and access_request.user_id != user.id:
        # Deliberately 404, not 403 — see module docstring.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")

    return access_request


@router.post("", response_model=AccessRequestOut, status_code=status.HTTP_201_CREATED)
async def create_access_request(
    body: AccessRequestCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    if "access_requests:create" not in _permission_names(current_user) and "ADMIN" not in _role_names(current_user):
        await write_audit_log(
            db, actor=current_user, action="ACCESS_DENIED", target_type="access_requests",
            source_ip=client_ip(request), result="DENIED", severity="MEDIUM",
            metadata={"required_permission": "access_requests:create"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not authorized to create access requests.")

    try:
        return await _service.create_request(
            db,
            requester=current_user,
            asset_id=body.asset_id,
            application_id=body.application_id,
            protocol=body.protocol,
            reason=body.reason,
            requested_duration=body.requested_duration,
            source_ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except InvalidTargetError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))


@router.get("", response_model=PaginatedResponse[AccessRequestDetailOut])
async def list_access_requests(
    pagination: PaginationParams = Depends(),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    if not _can_view_all(current_user) and not _can_view_own(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not authorized to view access requests.")

    query = select(AccessRequest)
    if not _can_view_all(current_user):
        query = query.where(AccessRequest.user_id == current_user.id)
    if status_filter:
        query = query.where(AccessRequest.status == status_filter)

    query = apply_sorting(query, AccessRequest, pagination.sort_by, pagination.sort_order, _SORTABLE_COLUMNS)
    # Newest first unless an allowlisted sort was asked for (as the sessions and recordings lists do):
    # without an ORDER BY, LIMIT/OFFSET pages are arbitrary and a new request can land on any page.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(AccessRequest.created_at.desc(), AccessRequest.id)
    page = await paginate(db, query, pagination, schema=AccessRequestDetailOut)
    # Each item carries its grant summary (one batched query), so a client never needs a detail call per
    # request just to know which ones can be launched; that pattern exhausted the API rate limit.
    ids = [item.id for item in page.items]
    if ids:
        grants = (await db.execute(
            select(JITGrant).where(JITGrant.request_id.in_(ids)).order_by(JITGrant.granted_at.desc())
        )).scalars().all()
        newest = {}
        for grant in grants:
            newest.setdefault(grant.request_id, grant)
        now = datetime.now(timezone.utc)
        for item in page.items:
            grant = newest.get(item.id)
            if grant is not None:
                summary = JITGrantSummary.model_validate(grant)
                if summary.status == "ACTIVE" and summary.expires_at <= now:
                    summary.status = "EXPIRED"  # read-only view, as in the detail endpoint
                item.jit_grant = summary
    return page


@router.get("/{request_id}", response_model=AccessRequestDetailOut)
async def get_access_request(
    request_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    if not _can_view_all(current_user) and not _can_view_own(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not authorized to view access requests.")
    access_request = await _get_visible_request_or_404(db, request_id, current_user)

    grant = (
        await db.execute(
            select(JITGrant)
            .where(JITGrant.request_id == access_request.id)
            .order_by(JITGrant.granted_at.desc())
        )
    ).scalars().first()
    detail = AccessRequestDetailOut.model_validate(access_request)
    if grant is not None:
        summary = JITGrantSummary.model_validate(grant)
        # Read-only view: report a lapsed grant as EXPIRED without writing.
        if summary.status == "ACTIVE" and summary.expires_at <= datetime.now(timezone.utc):
            summary.status = "EXPIRED"
        detail.jit_grant = summary
    return detail


@router.post("/{request_id}/cancel", response_model=AccessRequestOut)
async def cancel_access_request(
    request_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    access_request = await _get_visible_request_or_404(db, request_id, current_user)

    if access_request.user_id != current_user.id and "ADMIN" not in _role_names(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only cancel your own access requests.")

    try:
        return await _service.cancel_request(db, access_request, current_user)
    except InvalidTransitionError as e:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Cannot cancel a request in status '{e.current}'."
        )
