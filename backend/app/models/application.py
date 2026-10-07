"""
Application model — represents internal web applications accessible through the PAM gateway.

SECURITY: Target URLs are stored server-side.
The frontend NEVER specifies the proxy destination.
Access is via /apps/{application_id}/session — NOT /proxy?url=<arbitrary>.
"""

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Application(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "applications"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Target configuration — stored server-side only
    target_url: Mapped[str] = mapped_column(
        String(2048), nullable=False,
        comment="Full target URL — never exposed to frontend users"
    )
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, default="HTTPS",
        comment="HTTP, HTTPS"
    )
    target_host: Mapped[str] = mapped_column(String(255), nullable=False)
    target_port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)

    # Risk and access
    risk_level: Mapped[str] = mapped_column(
        String(10), nullable=False, default="MEDIUM",
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    proxy_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="STANDARD_PROXY",
        comment="STANDARD_PROXY, ISOLATED_BROWSER"
    )

    # Policy controls
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    recording_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    download_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    upload_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    clipboard_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    session_timeout: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30,
        comment="Session timeout in minutes"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE",
        comment="ACTIVE, INACTIVE, MAINTENANCE"
    )

    # Reference to assigned policy
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )

    # Soft delete
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Application {self.name} ({self.proxy_mode})>"
