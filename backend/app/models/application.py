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

    # Target configuration — stored server-side only. target_url is NEVER
    # accepted as client input (see app/schemas/applications.py +
    # app/core/ssrf.py) — it is always derived from hostname/port/protocol
    # after SSRF validation, so a client can't smuggle a mismatched or
    # credential-embedded URL past the hostname/port checks.
    target_url: Mapped[str] = mapped_column(
        String(2048), nullable=False,
        comment="Derived server-side from hostname/port/protocol — never accepted as direct input"
    )
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, default="HTTPS",
        comment="HTTP, HTTPS"
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)

    # Risk and access
    environment: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PRODUCTION", index=True,
        comment="DEVELOPMENT, TEST, STAGING, PRODUCTION"
    )
    criticality: Mapped[str] = mapped_column(
        String(10), nullable=False, default="MEDIUM", index=True,
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    access_mode: Mapped[str] = mapped_column(
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
    # Where the isolated browser starts: a path on the registered origin only (never a full URL).
    start_path: Mapped[str] = mapped_column(
        String(512), nullable=False, default="/", server_default="/",
        comment="Path on the registered origin the isolated browser opens"
    )
    # Explicit, admin-set trust for a certificate that does not validate publicly (self-signed or
    # wrong name): the base64 SHA-256 of the server's SubjectPublicKeyInfo. Only that exact key is
    # accepted for this application; null means normal certificate validation only.
    tls_pin_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
        comment="Pinned server key (base64 SHA-256 of SPKI) for an explicitly trusted certificate"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE",
        comment="ACTIVE, INACTIVE, MAINTENANCE"
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Reference to assigned policy
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )

    # Audit trail — who registered/last changed this application
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Soft delete
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Application {self.name} ({self.access_mode})>"
