"""
Policy model — configurable access policies evaluated by the Policy Engine.

Policies define what controls are required at each risk level.
The backend evaluates policies — not the frontend.
"""

from typing import Optional

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Policy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Risk threshold — policy applies when risk >= this level
    risk_threshold: Mapped[str] = mapped_column(
        String(10), nullable=False, default="LOW",
        comment="LOW, MEDIUM, HIGH, CRITICAL"
    )
    min_risk_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Minimum numeric risk score for this policy to apply"
    )

    # Required controls
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    jit_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    recording_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Session restrictions
    session_timeout: Mapped[int] = mapped_column(
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
        comment="If true, access is denied (CRITICAL risk default)"
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<Policy {self.name} (risk>={self.risk_threshold})>"
