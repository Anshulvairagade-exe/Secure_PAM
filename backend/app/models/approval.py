"""
Approval model — tracks approval/rejection decisions.

Every approval is recorded with:
- Who approved/rejected
- When
- Why (comment)
- Source context (IP)
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

    # Approver
    approver_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    # Decision
    decision: Mapped[str] = mapped_column(
        String(20), nullable=False,
        comment="APPROVED, REJECTED"
    )
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Context
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    def __repr__(self) -> str:
        return f"<Approval {self.request_id} ({self.decision})>"
