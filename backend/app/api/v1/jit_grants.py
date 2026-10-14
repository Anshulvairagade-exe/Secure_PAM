"""
JIT grant administration.

Grants are issued on approval and normally die by expiry. This router lets
an administrator kill one early: revoking a grant marks it REVOKED and
ends every live session it authorized (fail closed — a session must never
outlive its JIT access). The SSH gateway monitor reads the same row, so a
revoked grant also tears down the real connection within its poll loop.

Admin-only (sessions:terminate). Revocation is idempotent: revoking an
already-dead grant reports its current state. Responses carry IDs and
reason codes only — never credentials or tokens.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.models.jit_grant import JITGrant
from app.models.session import Session
from app.models.user import User
from app.services.jit_service import JITService

router = APIRouter(prefix="/jit-grants", tags=["JIT Grants"])

LIVE_SESSION_STATUSES = {"CREATED", "STARTING", "ACTIVE"}


class GrantRevokeOut(BaseModel):
    id: uuid.UUID
    status: str
    revoked_at: Optional[datetime] = None
    sessions_ended: int


@router.post("/{grant_id}/revoke", response_model=GrantRevokeOut)
async def revoke_grant(
    grant_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "terminate")),
):
    """Revoke a JIT grant now. Live sessions bound to it end as EXPIRED
    with a SESSION_ENDED_BY_GRANT event; the gateway monitor closes the
    underlying connections. Audited as JIT_REVOKED."""
    grant = await db.get(JITGrant, grant_id)
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "JIT grant not found")

    ended = 0
    if grant.status == "ACTIVE":
        live = (
            await db.execute(
                select(Session.id).where(
                    Session.jit_grant_id == grant.id,
                    Session.status.in_(LIVE_SESSION_STATUSES),
                )
            )
        ).scalars().all()
        ended = len(live)
        await JITService().revoke(db, grant)

    await write_audit_log(
        db,
        actor=current_user,
        action="JIT_REVOKED",
        target_type="jit_grant",
        target_id=str(grant.id),
        request_id=grant.request_id,
        source_ip=client_ip(request),
        result="SUCCESS",
        severity="HIGH",
        metadata={
            "grant_status": grant.status,
            "grantee_user_id": str(grant.user_id),
            "asset_id": str(grant.asset_id) if grant.asset_id else None,
            "sessions_ended": ended,
        },
    )
    await db.commit()
    return GrantRevokeOut(
        id=grant.id, status=grant.status, revoked_at=grant.revoked_at, sessions_ended=ended
    )
