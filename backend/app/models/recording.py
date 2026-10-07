"""
Recording model — metadata for session recordings.

Recordings are stored on disk (or object storage), NOT in the database.
This model stores metadata, file references, and access control information.

SECURITY: Recordings are served through authenticated endpoints only.
No predictable public URLs. RBAC enforced before serving.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Recording(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "recordings"

    # Session reference
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Recording type
    recording_type: Mapped[str] = mapped_column(
        String(20), nullable=False,
        comment="VIDEO (RDP), TERMINAL (SSH), HTTP (Web)"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING",
        comment="PENDING, RECORDING, COMPLETED, FAILED, DELETED"
    )

    # File metadata — path is server-side only
    file_path: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True,
        comment="Server-side path — never exposed to frontend"
    )
    file_size: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True, comment="Size in bytes"
    )
    file_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True,
        comment="SHA-256 hash for integrity verification"
    )
    duration_seconds: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )

    # Retention
    retention_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Date after which recording can be deleted"
    )

    # Additional metadata
    metadata_: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    def __repr__(self) -> str:
        return f"<Recording {self.id} ({self.recording_type}, {self.status})>"
