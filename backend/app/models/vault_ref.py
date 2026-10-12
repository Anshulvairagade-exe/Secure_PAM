"""
Vault Reference model — tracks which assets/applications have secrets stored in Vault.

IMPORTANT: This table stores REFERENCES to vault paths, NOT the secrets themselves.
Secrets are retrieved on-demand from Vault and passed directly to gateways.

`vault_path` is relative to the provider's KV mount (no "secret/" and no
"data/" segment) and must sit under OPENBAO_SECRET_PATH_PREFIX — see
app/secret_providers/paths.py. It is only ever written by the admin
credential-ref API, which derives it server-side; CredentialService
re-validates it on every read.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class VaultRef(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vault_refs"

    # Target reference — either asset OR application
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Which provider holds the secret. Must match the running
    # SECRET_PROVIDER, or retrieval is refused (no cross-provider fallback).
    provider: Mapped[str] = mapped_column(
        String(20), nullable=False, default="openbao", server_default="openbao",
        comment="openbao, mock"
    )

    # Vault path reference — NOT the secret
    vault_path: Mapped[str] = mapped_column(
        String(512), nullable=False,
        comment="Path relative to the KV mount, like securepam/assets/test-linux-01"
    )
    secret_version: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Pinned KV v2 version; null reads the latest"
    )

    # Secret metadata
    secret_type: Mapped[str] = mapped_column(
        String(20), nullable=False,
        comment="PASSWORD, SSH_KEY, API_KEY, CERTIFICATE"
    )
    username: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Username associated with the secret (not the secret itself)"
    )

    # Rotation
    last_rotated: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rotation_interval_days: Mapped[Optional[int]] = mapped_column(nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<VaultRef {self.vault_path} ({self.secret_type})>"
