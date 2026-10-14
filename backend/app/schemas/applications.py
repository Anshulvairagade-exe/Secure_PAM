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

import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import field_validator, BaseModel, ConfigDict, Field

from app.schemas.enums import AccessMode, Criticality, Environment, Protocol


_PIN_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")


def validate_start_path(value: str) -> str:
    """A path on the registered origin: must start with a single "/", no scheme, no authority
    ("//host"), no backslashes, query, fragment or control characters, so it can never retarget the
    browser to another origin. A trailing bare "?" is dropped."""
    path = value.strip()
    if path.endswith("?"):
        path = path[:-1]
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "?" in path or "#" in path \
            or not _PATH_RE.match(path) or ".." in path.split("/"):
        raise ValueError("start_path must be a plain absolute path on the registered host, e.g. /app/login")
    return path


def validate_tls_pin(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    if not _PIN_RE.match(value):
        raise ValueError("tls_pin_sha256 must be the base64 SHA-256 of the server's SubjectPublicKeyInfo (44 chars)")
    return value


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
    start_path: str = Field(default="/", max_length=512)
    tls_pin_sha256: Optional[str] = Field(default=None, max_length=64)

    @field_validator("start_path")
    @classmethod
    def _path(cls, v: str) -> str:
        return validate_start_path(v)

    @field_validator("tls_pin_sha256")
    @classmethod
    def _pin(cls, v: Optional[str]) -> Optional[str]:
        return validate_tls_pin(v)


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
    start_path: Optional[str] = Field(default=None, max_length=512)
    tls_pin_sha256: Optional[str] = Field(default=None, max_length=64)

    @field_validator("start_path")
    @classmethod
    def _path(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else validate_start_path(v)

    @field_validator("tls_pin_sha256")
    @classmethod
    def _pin(cls, v: Optional[str]) -> Optional[str]:
        return validate_tls_pin(v)


class ApplicationOut(ApplicationBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_url: str
    status: str
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None
