"""
Access Request model — the core workflow entity.

Lifecycle (enforced server-side — see app/services/access_decision.py's
ALLOWED_TRANSITIONS, never trust a client-supplied status):

    PENDING ──────────┬─→ APPROVAL_REQUIRED ─┬─→ APPROVED ─┬─→ ACTIVE ─→ EXPIRED
                       │                      ├─→ REJECTED │
                       ├─→ APPROVED ──────────┘             └─→ EXPIRED
                       ├─→ DENIED
                       ├─→ CANCELLED
                       └─→ EXPIRED

In practice PENDING is transient: AccessDecisionService resolves a new
request synchronously at creation time (policy + risk evaluation run
immediately), so a persisted row is read back as APPROVAL_REQUIRED,
APPROVED, or DENIED, never left sitting at PENDING. The state is kept as
the formal starting point for a future async/queued evaluation model.

Every access request triggers risk evaluation and policy check — both
snapshotted onto this row (risk_score/risk_level/risk_factors,
policy_decision) so the decision that was actually made stays legible
even if the Policy it was based on changes later.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class AccessRequest(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "access_requests"
    __table_args__ = (Index("ix_access_requests_created_at", "created_at"),)

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
        comment="PENDING, APPROVAL_REQUIRED, APPROVED, REJECTED, DENIED, EXPIRED, CANCELLED, ACTIVE"
    )

    # Risk evaluation results — see app/risk/engine.py
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True,
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    risk_factors: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Policy evaluation result — see app/policies/evaluator.py. Snapshotted
    # (not just policy_id) so the decision stays legible even if the Policy
    # row is edited or soft-deleted afterward.
    policy_decision: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )

    # Controls resolved by the decision service at creation time — these
    # are what the rest of the workflow (approval queue, JIT grant) acts
    # on, never re-derived from the (possibly since-changed) Policy row.
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    jit_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recording_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Request context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Timestamps
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When this request expires if not acted upon"
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When the final decision (APPROVED/REJECTED/DENIED) was made"
    )
    decided_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        comment="Approver who decided this, or null for an automatic policy/risk decision"
    )

    def __repr__(self) -> str:
        return f"<AccessRequest {self.request_number} ({self.status})>"
