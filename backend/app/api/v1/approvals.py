"""
Approval endpoints — the human half of the access-request decision
workflow. All state-changing logic (self-approval prevention, state-
transition validation, JIT grant creation) lives in
app/services/access_decision.py, not here — see that module's docstring
for why there are no duplicate /access-requests/{id}/approve|reject
routes alongside these.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip
from app.core.deps import PermissionChecker, get_db
from app.core.pagination import apply_sorting, paginate
from app.models.access_request import AccessRequest
from app.models.approval import Approval
from app.models.user import User
from app.schemas.approvals import ApproveInput, ApprovalOut, RejectInput
from app.schemas.common import PaginatedResponse, PaginationParams
from app.services.access_decision import (
    AccessDecisionService,
    InvalidTransitionError,
    SelfApprovalError,
)

router = APIRouter(prefix="/approvals", tags=["approvals"])

_SORTABLE_COLUMNS = {"created_at", "status", "decided_at"}
_service = AccessDecisionService()


async def _get_approval_and_request_or_404(db: AsyncSession, approval_id: UUID) -> tuple[Approval, AccessRequest]:
    result = await db.execute(select(Approval).where(Approval.id == approval_id))
    approval = result.scalar_one_or_none()
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")

    req_result = await db.execute(select(AccessRequest).where(AccessRequest.id == approval.request_id))
    access_request = req_result.scalar_one_or_none()
    if access_request is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Associated access request not found")

    return approval, access_request


@router.get("", response_model=PaginatedResponse[ApprovalOut])
async def list_approvals(
    pagination: PaginationParams = Depends(),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("approvals", "read")),
):
    query = select(Approval)
    if status_filter:
        query = query.where(Approval.status == status_filter)

    query = apply_sorting(query, Approval, pagination.sort_by, pagination.sort_order, _SORTABLE_COLUMNS)
    return await paginate(db, query, pagination, schema=ApprovalOut)


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_approval(
    approval_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("approvals", "read")),
):
    approval, _ = await _get_approval_and_request_or_404(db, approval_id)
    return approval


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
async def approve_request(
    approval_id: UUID,
    body: ApproveInput,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("approvals", "approve")),
):
    approval, access_request = await _get_approval_and_request_or_404(db, approval_id)
    try:
        await _service.approve(
            db, approval=approval, access_request=access_request, approver=current_user,
            comment=body.comment, source_ip=client_ip(request),
        )
    except SelfApprovalError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))
    except InvalidTransitionError:
        raise HTTPException(status.HTTP_409_CONFLICT, f"This approval has already been decided ({approval.status}).")
    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalOut)
async def reject_request(
    approval_id: UUID,
    body: RejectInput,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("approvals", "reject")),
):
    approval, access_request = await _get_approval_and_request_or_404(db, approval_id)
    try:
        await _service.reject(
            db, approval=approval, access_request=access_request, approver=current_user,
            comment=body.comment, source_ip=client_ip(request),
        )
    except SelfApprovalError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))
    except InvalidTransitionError:
        raise HTTPException(status.HTTP_409_CONFLICT, f"This approval has already been decided ({approval.status}).")
    return approval
