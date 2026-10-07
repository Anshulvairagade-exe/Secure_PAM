"""
Policy model — configurable access policies evaluated by the (future) Risk
and Policy Engines. The backend evaluates policies — never the frontend.

allowed_* / allowed_days are PostgreSQL ARRAY columns: empty/null means
"no restriction on this dimension" (applies to everything), a non-empty
array restricts to exactly those values. Validated against the matching
enum in app/schemas/enums.py at the API layer, not via a DB CHECK
constraint — consistent with how every other model in this codebase
validates its string fields.
"""

import uuid
from typing import List, Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Policy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Scope — which requests this policy applies to. Empty/null = no
    # restriction on that dimension (applies to all roles/types/etc).
    allowed_roles: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(20)), nullable=True)
    allowed_asset_types: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(30)), nullable=True)
    allowed_environments: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(20)), nullable=True)
    allowed_protocols: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(10)), nullable=True)
    allowed_days: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String(3)), nullable=True, comment="MON..SUN; empty/null = every day"
    )
    business_hours_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Risk threshold — policy applies when risk >= this level
    risk_threshold: Mapped[str] = mapped_column(
        String(10), nullable=False, default="LOW",
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    min_risk_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Minimum numeric risk score for this policy to apply — consumed by the future Risk Engine"
    )

    # Required controls
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    jit_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_recording: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Session restrictions
    max_session_duration: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30,
        comment="Max session duration in minutes"
    )
    download_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    upload_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    clipboard_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Policy behavior
    auto_approve: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False,
        comment="If true, low-risk requests are auto-approved"
    )
    deny_access: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False,
        comment="If true, access is denied outright (CRITICAL risk default)"
    )

    # Audit trail
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Soft delete — Assets/Applications referencing a deleted policy keep
    # working (policy_id is ON DELETE SET NULL at the DB level if ever hard
    # deleted), but we soft-delete here too so policy history/audit stays
    # intact, consistent with Asset/Application.
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Policy {self.name} (risk>={self.risk_threshold})>"
