"""Asset CRUD schemas. Create/Update intentionally never accept id/timestamps/
created_by/updated_by/is_deleted — those are always server-controlled."""

import ipaddress
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.enums import AssetType, Criticality, Environment, Protocol


class AssetBase(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str
    port: int = Field(ge=1, le=65535)
    protocol: Protocol
    asset_type: AssetType
    environment: Environment = Environment.DEVELOPMENT
    criticality: Criticality = Criticality.MEDIUM
    description: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=255)
    enabled: bool = True
    recording_required: bool = False
    approval_required: bool = False
    jit_required: bool = True
    policy_id: Optional[UUID] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    """PATCH semantics — every field optional, applied via exclude_unset."""

    model_config = ConfigDict(use_enum_values=True)

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=255)
    ip_address: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Protocol] = None
    asset_type: Optional[AssetType] = None
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    description: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=255)
    enabled: Optional[bool] = None
    recording_required: Optional[bool] = None
    approval_required: Optional[bool] = None
    jit_required: Optional[bool] = None
    policy_id: Optional[UUID] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class AssetOut(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None
