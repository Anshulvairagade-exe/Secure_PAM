"""
JITService — the single authoritative source of truth for "is this
just-in-time grant currently valid?"

This is explicitly NOT a UI countdown. Every future gateway integration
(Guacamole/RDP, SSH, Web) must call `validate()` before establishing a
session; none of them — and no frontend timer — gets to decide for
itself whether access is still live. `grant()` is the only place an
expiry is ever computed, and it always clamps to the policy/decision
maximum — a caller cannot hand it an arbitrary duration and expect it
honored past that ceiling (see app/services/access_decision.py, which is
the only caller of `grant()`).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.jit_grant import JITGrant


class JITService:
    async def grant(
        self,
        db: AsyncSession,
        *,
        request_id: UUID,
        user_id: UUID,
        asset_id: Optional[UUID],
        application_id: Optional[UUID],
        protocol: str,
        duration_minutes: int,
        created_by: Optional[UUID],
    ) -> JITGrant:
        now = datetime.now(timezone.utc)
        grant = JITGrant(
            request_id=request_id,
            user_id=user_id,
            asset_id=asset_id,
            application_id=application_id,
            protocol=protocol,
            granted_at=now,
            expires_at=now + timedelta(minutes=duration_minutes),
            status="ACTIVE",
            created_by=created_by,
        )
        db.add(grant)
        await db.flush()
        return grant

    def is_active(self, grant: JITGrant) -> bool:
        """Pure check against an already-loaded grant — no DB access, no
        side effects. Use `validate()` instead when you need the
        authoritative, up-to-date answer (it also flips a stale ACTIVE
        row to EXPIRED)."""
        return grant.status == "ACTIVE" and grant.expires_at > datetime.now(timezone.utc)

    async def validate(
        self, db: AsyncSession, *, user_id: UUID, target_id: UUID, protocol: str
    ) -> Optional[JITGrant]:
        """
        Returns the live JITGrant if `user_id` currently holds valid JIT
        access to `target_id` over `protocol`, else None. `target_id` is
        matched against whichever of asset_id/application_id is set on
        the grant — callers don't need to know which kind of target it is.

        Opportunistically flips a found-but-expired ACTIVE row to EXPIRED
        (and writes nothing further — JIT_EXPIRED auditing is the caller's
        job, since only it knows the request context) so stale grants
        don't linger as ACTIVE purely because nothing looked at them
        since they lapsed.
        """
        result = await db.execute(
            select(JITGrant)
            .where(
                JITGrant.user_id == user_id,
                JITGrant.protocol == protocol,
                or_(JITGrant.asset_id == target_id, JITGrant.application_id == target_id),
                JITGrant.status == "ACTIVE",
            )
            .order_by(JITGrant.granted_at.desc())
        )
        grant = result.scalars().first()
        if grant is None:
            return None

        if grant.expires_at <= datetime.now(timezone.utc):
            grant.status = "EXPIRED"
            await db.flush()
            return None

        return grant

    async def revoke(self, db: AsyncSession, grant: JITGrant) -> JITGrant:
        if grant.status == "ACTIVE":
            grant.status = "REVOKED"
            grant.revoked_at = datetime.now(timezone.utc)
            await db.flush()
        return grant

    async def expire(self, db: AsyncSession, grant: JITGrant) -> JITGrant:
        if grant.status == "ACTIVE":
            grant.status = "EXPIRED"
            await db.flush()
        return grant
