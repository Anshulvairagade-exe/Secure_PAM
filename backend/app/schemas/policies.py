"""
Policy CRUD schemas.

allowed_* lists are optional: null/empty means "no restriction on this
dimension". Validated as lists of the matching enum so an invalid entry
(e.g. a typo'd role name) is rejected with a 422, not silently stored.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import AssetType, DayOfWeek, Environment, Protocol, RiskLevel, RoleName


class PolicyBase(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    enabled: bool = True

    allowed_roles: Optional[List[RoleName]] = None
    allowed_asset_types: Optional[List[AssetType]] = None
    allowed_environments: Optional[List[Environment]] = None
    allowed_protocols: Optional[List[Protocol]] = None
    allowed_days: Optional[List[DayOfWeek]] = None
    business_hours_only: bool = False

    risk_threshold: RiskLevel = RiskLevel.LOW
    min_risk_score: int = Field(default=0, ge=0, le=100)

    require_approval: bool = False
    jit_required: bool = True
    require_mfa: bool = True
    require_recording: bool = False

    max_session_duration: int = Field(default=30, ge=1, le=480)
    download_allowed: bool = True
    upload_allowed: bool = True
    clipboard_allowed: bool = True

    auto_approve: bool = False
    deny_access: bool = False


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    """PATCH semantics — every field optional, applied via exclude_unset."""

    model_config = ConfigDict(use_enum_values=True)

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    enabled: Optional[bool] = None

    allowed_roles: Optional[List[RoleName]] = None
    allowed_asset_types: Optional[List[AssetType]] = None
    allowed_environments: Optional[List[Environment]] = None
    allowed_protocols: Optional[List[Protocol]] = None
    allowed_days: Optional[List[DayOfWeek]] = None
    business_hours_only: Optional[bool] = None

    risk_threshold: Optional[RiskLevel] = None
    min_risk_score: Optional[int] = Field(default=None, ge=0, le=100)

    require_approval: Optional[bool] = None
    jit_required: Optional[bool] = None
    require_mfa: Optional[bool] = None
    require_recording: Optional[bool] = None

    max_session_duration: Optional[int] = Field(default=None, ge=1, le=480)
    download_allowed: Optional[bool] = None
    upload_allowed: Optional[bool] = None
    clipboard_allowed: Optional[bool] = None

    auto_approve: Optional[bool] = None
    deny_access: Optional[bool] = None


class PolicyOut(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None
