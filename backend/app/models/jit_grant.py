"""
JIT (Just-In-Time) Grant model — time-bounded access grants.

Lifecycle:
    ACTIVE → EXPIRED/REVOKED

Server-side enforcement:
- Backend checks expiry on every session/access attempt
- Redis TTL triggers background expiry task
- Frontend timer is cosmetic only — never trusted
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class JITGrant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "jit_grants"

    # Reference to access request
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), nullable=False, index=True
    )

    # Grantee
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    # Target — either asset OR application. Kept as two typed FKs (not a
    # generic target_type/target_id pair) for the same reason AccessRequest
    # does — real referential integrity. JITService.validate()'s public
    # signature still takes a single target_id, matching it against
    # whichever of the two columns is set.
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="SET NULL"), nullable=True
    )
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, comment="RDP, SSH, HTTP, HTTPS")

    # Who created this grant — the approver for a human-approved request,
    # or null for an automatic (policy+risk) approval.
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Time bounds — enforced server-side
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE", index=True,
        comment="ACTIVE, EXPIRED, REVOKED"
    )

    def __repr__(self) -> str:
        return f"<JITGrant {self.id} ({self.status}, expires={self.expires_at})>"
