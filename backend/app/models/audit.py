"""
Audit Log model — structured security event logging.

Every privileged action generates an audit event.
Secrets are NEVER logged.

Events are designed to be exportable to SIEM systems (Wazuh).
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDMixin


class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_logs"

    # Unique event identifier
    event_id: Mapped[str] = mapped_column(
        String(30), unique=True, nullable=False, index=True,
        comment="Human-readable event ID like EVT-A1B2C3D4"
    )

    # When
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Who
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_username: Mapped[str] = mapped_column(
        String(150), nullable=False, index=True
    )

    # What
    action: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="LOGIN_SUCCESS, ACCESS_REQUEST_CREATED, JIT_GRANTED, etc."
    )

    # Target
    target_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True,
        comment="asset, application, user, session, etc."
    )
    target_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )

    # Context references
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    request_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Network context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Result
    result: Mapped[str] = mapped_column(
        String(20), nullable=False, default="SUCCESS",
        comment="SUCCESS, FAILURE, DENIED"
    )

    # Severity
    severity: Mapped[str] = mapped_column(
        String(10), nullable=False, default="INFO", index=True,
        comment="INFO, LOW, MEDIUM, HIGH, CRITICAL"
    )

    # Additional details — NEVER include secrets
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_id} ({self.action}, {self.severity})>"


class RiskEvent(Base, UUIDMixin):
    """Records risk evaluations for analysis and reporting."""
    __tablename__ = "risk_events"

    # Reference
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    # Risk result
    risk_score: Mapped[int] = mapped_column(nullable=False)
    risk_level: Mapped[str] = mapped_column(String(10), nullable=False)
    risk_factors: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Context
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<RiskEvent score={self.risk_score} ({self.risk_level})>"
