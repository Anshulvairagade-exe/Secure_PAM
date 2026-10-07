"""
Application CRUD schemas.

SECURITY: `target_url` is deliberately NOT a field on ApplicationCreate/
ApplicationUpdate — clients provide hostname/port/protocol, which are
SSRF-validated (app/core/ssrf.py) in the endpoint, and target_url is
derived server-side from those validated values. This is what "do not
allow user-controlled destination URLs" means structurally, not just as
a runtime check: there's no field for a client to put an arbitrary URL
into in the first place.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import AccessMode, Criticality, Environment, Protocol


class ApplicationBase(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.HTTPS
    environment: Environment = Environment.PRODUCTION
    criticality: Criticality = Criticality.MEDIUM
    access_mode: AccessMode = AccessMode.STANDARD_PROXY
    enabled: bool = True
    approval_required: bool = False
    mfa_required: bool = True
    recording_required: bool = False
    download_allowed: bool = False
    upload_allowed: bool = False
    clipboard_allowed: bool = False
    session_timeout: int = Field(default=30, ge=1, le=480)
    policy_id: Optional[UUID] = None


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationUpdate(BaseModel):
    """PATCH semantics — every field optional, applied via exclude_unset."""

    model_config = ConfigDict(use_enum_values=True)

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Protocol] = None
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    access_mode: Optional[AccessMode] = None
    enabled: Optional[bool] = None
    approval_required: Optional[bool] = None
    mfa_required: Optional[bool] = None
    recording_required: Optional[bool] = None
    download_allowed: Optional[bool] = None
    upload_allowed: Optional[bool] = None
    clipboard_allowed: Optional[bool] = None
    session_timeout: Optional[int] = Field(default=None, ge=1, le=480)
    policy_id: Optional[UUID] = None


class ApplicationOut(ApplicationBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_url: str
    status: str
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None
