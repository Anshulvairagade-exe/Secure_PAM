"""
Asset model — represents target servers/machines that users request access to.

Asset types: WINDOWS_SERVER, WINDOWS_WORKSTATION, LINUX_SERVER, UNIX_SERVER,
             NETWORK_DEVICE, OTHER
Protocols: RDP, SSH, HTTPS, HTTP
Users cannot specify arbitrary targets — only registered, approved assets.
Credentials are NEVER stored here — see app/models/vault_ref.py; actual
secret retrieval is a future OpenBao/Vault phase.
"""

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, index=True,
        comment="RDP, SSH, HTTPS, HTTP"
    )
    asset_type: Mapped[str] = mapped_column(
        String(30), nullable=False, index=True,
        comment="WINDOWS_SERVER, WINDOWS_WORKSTATION, LINUX_SERVER, UNIX_SERVER, NETWORK_DEVICE, OTHER"
    )
    environment: Mapped[str] = mapped_column(
        String(20), nullable=False, default="DEVELOPMENT", index=True,
        comment="DEVELOPMENT, TEST, STAGING, PRODUCTION"
    )
    criticality: Mapped[str] = mapped_column(
        String(10), nullable=False, default="MEDIUM", index=True,
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVE",
        comment="ACTIVE, INACTIVE, MAINTENANCE"
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Policy controls
    recording_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    jit_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Reference to assigned policy
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )

    # Audit trail — who registered/last changed this asset
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Soft delete
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Asset {self.name} ({self.protocol})>"
