"""
Concurrent privileged-session limit.

The cap is per user and counts sessions that actually hold a gateway slot:
ACTIVE, TERMINATING (still tearing down) and STARTING ones whose one-time
ticket can still be redeemed. Approved requests and unused JIT grants never
count. A STARTING session older than its ticket's lifetime can no longer
connect, so it is closed out as abandoned rather than blocking the user.

Atomicity: `acquire_slot` takes a row lock on the user (SELECT ... FOR
UPDATE), counts, and returns with the lock still held. The caller inserts
its Session and commits in the same transaction, so two simultaneous
launches by one user serialize and the second sees the first.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.config import settings
from app.models.app_setting import AppSetting
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.ssh_ticket import SSHTicketService

LIMIT_KEY = "max_concurrent_sessions"
MIN_LIMIT, MAX_LIMIT = 1, 20
# Ticket lifetime plus margin for the websocket handshake.
STARTING_GRACE = timedelta(seconds=SSHTicketService.DEFAULT_TTL_SECONDS + 30)
SLOT_STATUSES = ("ACTIVE", "TERMINATING")


async def get_limit(db: AsyncSession) -> int:
    row = await db.get(AppSetting, LIMIT_KEY)
    value = row.value if row is not None else settings.MAX_CONCURRENT_SESSIONS
    return value if isinstance(value, int) and MIN_LIMIT <= value <= MAX_LIMIT else settings.MAX_CONCURRENT_SESSIONS


async def set_limit(db: AsyncSession, value: int, actor: User) -> int:
    """Persist the limit; the caller validates the range, audits and commits."""
    before = await get_limit(db)
    row = await db.get(AppSetting, LIMIT_KEY)
    if row is None:
        db.add(AppSetting(key=LIMIT_KEY, value=value, updated_by=actor.id))
    else:
        row.value, row.updated_by = value, actor.id
    return before


async def _close_abandoned(db: AsyncSession, user_id) -> None:
    cutoff = datetime.now(timezone.utc) - STARTING_GRACE
    stale = (await db.execute(
        select(Session).where(Session.user_id == user_id, Session.status.in_(("CREATED", "STARTING")),
                              Session.created_at < cutoff)
    )).scalars().all()
    now = datetime.now(timezone.utc)
    for session in stale:
        session.status, session.end_time = "FAILED", now
        db.add(SessionEvent(session_id=session.id, event_type="SESSION_FAILED", timestamp=now,
                            details={"reason": "LAUNCH_NOT_CONNECTED"}))
        if session.recording_id:
            recording = await db.get(Recording, session.recording_id)
            if recording and recording.status in ("PENDING", "RECORDING"):
                recording.status = "FAILED"


async def count_slots(db: AsyncSession, user_id) -> int:
    cutoff = datetime.now(timezone.utc) - STARTING_GRACE
    fresh_starting = (Session.status.in_(("CREATED", "STARTING"))) & (Session.created_at >= cutoff)
    return (await db.execute(
        select(func.count()).select_from(Session).where(
            Session.user_id == user_id, Session.status.in_(SLOT_STATUSES) | fresh_starting)
    )).scalar_one()


async def acquire_slot(
    db: AsyncSession, user: User, *, protocol: str, source_ip: Optional[str], request_id=None, asset_id=None,
) -> None:
    """Raise 409 when the user is at the limit. Otherwise return holding the user-row lock."""
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    await _close_abandoned(db, user.id)
    limit = await get_limit(db)
    active = await count_slots(db, user.id)
    if active >= limit:
        await write_audit_log(
            db, actor=user, action="SESSION_LAUNCH_DENIED", target_type="asset",
            target_id=str(asset_id) if asset_id else None, request_id=request_id, source_ip=source_ip,
            result="DENIED", severity="MEDIUM",
            metadata={"reason": "SESSION_LIMIT_REACHED", "protocol": protocol, "limit": limit, "active": active},
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Concurrent session limit reached ({active} of {limit} in use). End an existing session before starting another.",
        )
