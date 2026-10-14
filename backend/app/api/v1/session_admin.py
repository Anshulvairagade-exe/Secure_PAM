"""
Administrator view and control of a user's sessions and grants.

Everything here needs sessions:terminate (ADMIN). The target user comes from
the URL and is looked up server-side; nothing about identity, status or role
is taken from the request body. Terminations go through the shared
termination service, so the real gateway connection is closed and the
recording settled by what exists, exactly as for the single-session endpoint.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.services.browser_isolation import get_browser_isolation_gateway
from app.services.rdp_gateway import get_rdp_gateway
from app.services.session_policy import count_slots, get_limit
from app.services.session_termination import LIVE_STATUSES, terminate_session
from app.services.ssh_terminal_gateway import AsyncSSHTerminalGateway, get_terminal_gateway

router = APIRouter(tags=["Session administration"])


class UserSessionOut(BaseModel):
    id: uuid.UUID
    session_number: str
    asset_name: Optional[str]
    protocol: str
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    created_at: datetime
    recording_status: Optional[str]
    jit_grant_id: Optional[uuid.UUID]


class ReadyGrantOut(BaseModel):
    id: uuid.UUID
    request_id: uuid.UUID
    request_number: Optional[str]
    asset_name: Optional[str]
    protocol: str
    expires_at: datetime


class UserAccessOut(BaseModel):
    user_id: uuid.UUID
    username: str
    session_limit: int
    active_sessions: int
    sessions: List[UserSessionOut]
    ready_grants: List[ReadyGrantOut]


class TerminateAllBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(None, max_length=300)


async def _target(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None or user.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


@router.get("/users/{user_id}/sessions", response_model=UserAccessOut)
async def user_sessions(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("sessions", "terminate")),
):
    """Sessions (newest first) and, separately, approved grants not yet used for a live session."""
    user = await _target(db, user_id)
    rows = (await db.execute(
        select(Session).where(Session.user_id == user.id).order_by(Session.created_at.desc()).limit(50)
    )).scalars().all()
    sessions = []
    for row in rows:
        asset = await db.get(Asset, row.asset_id) if row.asset_id else None
        rec = await db.get(Recording, row.recording_id) if row.recording_id else None
        sessions.append(UserSessionOut(
            id=row.id, session_number=row.session_number, asset_name=asset.name if asset else None,
            protocol=row.protocol, status=row.status, start_time=row.start_time, end_time=row.end_time,
            created_at=row.created_at, recording_status=rec.status if rec else None, jit_grant_id=row.jit_grant_id,
        ))
    in_use = {r.jit_grant_id for r in rows if r.status in LIVE_STATUSES and r.jit_grant_id}
    grants = (await db.execute(
        select(JITGrant).where(JITGrant.user_id == user.id, JITGrant.status == "ACTIVE",
                               JITGrant.expires_at > datetime.now(timezone.utc))
        .order_by(JITGrant.expires_at)
    )).scalars().all()
    ready = []
    for grant in grants:
        if grant.id in in_use:
            continue
        req = await db.get(AccessRequest, grant.request_id)
        asset = await db.get(Asset, grant.asset_id) if grant.asset_id else None
        ready.append(ReadyGrantOut(
            id=grant.id, request_id=grant.request_id, request_number=req.request_number if req else None,
            asset_name=asset.name if asset else None, protocol=grant.protocol, expires_at=grant.expires_at))
    return UserAccessOut(
        user_id=user.id, username=user.username, session_limit=await get_limit(db),
        active_sessions=await count_slots(db, user.id), sessions=sessions, ready_grants=ready,
    )


@router.post("/users/{user_id}/sessions/terminate-all")
async def terminate_all(
    user_id: uuid.UUID,
    request: Request,
    body: Optional[TerminateAllBody] = None,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("sessions", "terminate")),
    gateway: AsyncSSHTerminalGateway = Depends(get_terminal_gateway),
    rdp_gateway=Depends(get_rdp_gateway),
    web_gateway=Depends(get_browser_isolation_gateway),
):
    """End every live session of a user and revoke the grants that authorized them.
    Per-session outcomes are reported; a failure on one never hides another's result."""
    user = await _target(db, user_id)
    reason = (body.reason if body else None) or "all sessions terminated by administrator"
    ids = (await db.execute(
        select(Session.id).where(Session.user_id == user.id, Session.status.in_(LIVE_STATUSES))
        .order_by(Session.created_at)
    )).scalars().all()
    results = []
    for session_id in ids:
        session = await db.get(Session, session_id)
        if session is None or session.status not in LIVE_STATUSES:
            continue
        results.append((await terminate_session(
            db, session, actor=actor, source_ip=client_ip(request), gateway=gateway, rdp_gateway=rdp_gateway, web_gateway=web_gateway, reason=reason,
            revoke_grant=True)).dict())
    complete = all(r["ok"] for r in results)
    await write_audit_log(
        db, actor=actor, action="USER_SESSIONS_TERMINATED", target_type="user", target_id=str(user.id),
        source_ip=client_ip(request), result="SUCCESS" if complete else "FAILURE", severity="HIGH",
        metadata={"username": user.username, "reason": reason, "sessions": len(results),
                  "failed": [r["session_number"] for r in results if not r["ok"]]},
    )
    await db.commit()
    payload = {"user_id": str(user.id), "complete": complete, "terminated": sum(r["ok"] for r in results),
               "results": results}
    return payload if complete else JSONResponse(payload, status_code=status.HTTP_207_MULTI_STATUS)
