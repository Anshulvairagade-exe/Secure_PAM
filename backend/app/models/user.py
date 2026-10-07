"""
User model — represents authenticated users synced from the IdP.

Stores only identity metadata and PAM-specific attributes.
Authentication is handled by the IdP (Keycloak).
Passwords are NEVER stored in this database.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.role import Role


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    # IdP-synced fields
    external_id: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=True, index=True,
        comment="Keycloak subject ID (sub claim)"
    )
    username: Mapped[str] = mapped_column(
        String(150), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # PAM-specific attributes
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system_user: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)

    # Dev mode only — hashed password for MockIdP
    # In production, passwords are managed by Keycloak
    hashed_password: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="DEV_MODE only — production uses Keycloak"
    )

    # Soft delete
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    roles: Mapped[List["UserRole"]] = relationship(
        "UserRole",
        back_populates="user",
        foreign_keys="UserRole.user_id",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class UserRole(Base, TimestampMixin):
    """Many-to-many association between users and roles."""
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    assigned_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User", back_populates="roles", foreign_keys=[user_id]
    )
    role: Mapped["Role"] = relationship("Role", back_populates="user_roles", lazy="selectin")
