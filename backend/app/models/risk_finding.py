"""
Risk Centre findings: one row per distinct, evidence-backed security issue.

Rows are produced by the deterministic detector (app.services.risk_detector, source
"securepam-detector") from SecurePAM's own audit and access-request records, or ingested from an
external source through POST /risk/findings/ingest. `fingerprint` is the dedupe key: re-evaluation
updates last_seen/occurrences/evidence instead of creating duplicates. Evidence holds references
(audit event ids, request numbers, counts), never secrets.
"""

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class RiskFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "risk_findings"

    fingerprint: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    rule_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, RESOLVED
    subject: Mapped[str] = mapped_column(String(255), nullable=False)  # what the finding is about (display)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True)
    evidence: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status_changed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status_note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
