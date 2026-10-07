"""
Access Request model — the core workflow entity.

Lifecycle:
    PENDING → APPROVED/REJECTED → ACTIVE → COMPLETED/EXPIRED/CANCELLED

Every access request triggers risk evaluation and policy check.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class AccessRequest(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "access_requests"

    # Human-readable identifier
    request_number: Mapped[str] = mapped_column(
        String(20), unique=True, nullable=False, index=True,
        comment="Human-readable ID like REQ-A1B2C"
    )

    # Requestor
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    # Target — either asset OR application (not both)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Request details
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False,
        comment="RDP, SSH, HTTP, HTTPS"
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_duration: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30,
        comment="Requested duration in minutes"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING", index=True,
        comment="PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED, ACTIVE, COMPLETED"
    )

    # Risk evaluation results
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True,
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Policy applied
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )

    # Request context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Timestamps
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When this request expires if not acted upon"
    )

    def __repr__(self) -> str:
        return f"<AccessRequest {self.request_number} ({self.status})>"
