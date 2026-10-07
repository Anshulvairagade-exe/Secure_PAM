"""
Approval model — tracks the approval queue and its decisions.

A row is created (status=PENDING) the moment AccessDecisionService
determines a request needs human approval, so it shows up in the
approver queue immediately — not retroactively once decided. decided_at/
comment/approver stay null until POST /approvals/{id}/approve|reject
resolves it.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Approval(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "approvals"

    # Reference to the access request
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), nullable=False, index=True
    )

    # Approver — null while PENDING (nobody has acted yet); set when decided.
    approver_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True
    )

    # Status — PENDING at creation, terminal once decided.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING", index=True,
        comment="PENDING, APPROVED, REJECTED"
    )
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Context — both null until decided.
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    def __repr__(self) -> str:
        return f"<Approval {self.request_id} ({self.status})>"
