"""
Notification model — in-app notifications for users.
"""

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Notification(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notifications"

    # Recipient
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Content
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Classification
    notification_type: Mapped[str] = mapped_column(
        String(30), nullable=False, default="INFO",
        comment="INFO, ACCESS_REQUEST, APPROVAL, SESSION, ALERT, SYSTEM"
    )
    severity: Mapped[str] = mapped_column(
        String(10), nullable=False, default="INFO",
        comment="INFO, LOW, MEDIUM, HIGH, CRITICAL"
    )

    # State
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Reference to related entity
    reference_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True,
        comment="access_request, session, jit_grant, etc."
    )
    reference_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<Notification {self.title} ({self.notification_type})>"
