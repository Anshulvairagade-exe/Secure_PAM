"""
Role and Permission models for RBAC.

Roles: ADMIN, OPERATOR, APPROVER, AUDITOR
Permissions are granular (resource + action).
Authorization is enforced server-side.
"""

import uuid
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, Column, ForeignKey, String, Table, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import UserRole


# Association table for role <-> permission
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", UUID(as_uuid=True), ForeignKey("permissions.id"), primary_key=True),
)


class Role(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False,
        comment="System roles cannot be deleted"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    permissions: Mapped[List["Permission"]] = relationship(
        "Permission", secondary=role_permissions, back_populates="roles", lazy="selectin"
    )
    user_roles: Mapped[List["UserRole"]] = relationship(
        "UserRole", back_populates="role"
    )

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class Permission(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    resource: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="Resource category: users, assets, sessions, etc."
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="Action: create, read, update, delete, approve, etc."
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        "Role", secondary=role_permissions, back_populates="permissions"
    )

    def __repr__(self) -> str:
        return f"<Permission {self.resource}:{self.action}>"
