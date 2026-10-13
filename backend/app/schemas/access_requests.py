"""
Access Request schemas.

Deliberately absent from AccessRequestCreate: requester_id, risk_score,
risk_level, risk_factors, policy_decision, approval_required,
jit_required, mfa_required, recording_required, status, expires_at.
Every one of those is calculated server-side by AccessDecisionService —
none of them are fields a client can set, by construction, not just by
convention.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.enums import Protocol


class AccessRequestCreate(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    asset_id: Optional[UUID] = None
    application_id: Optional[UUID] = None
    protocol: Protocol
    reason: str = Field(min_length=1, max_length=2000)
    requested_duration: int = Field(default=30, ge=1, le=480)

    @model_validator(mode="after")
    def exactly_one_target(self) -> "AccessRequestCreate":
        if bool(self.asset_id) == bool(self.application_id):
            raise ValueError("Exactly one of asset_id or application_id must be provided.")
        return self


class AccessRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_number: str
    user_id: UUID
    asset_id: Optional[UUID] = None
    application_id: Optional[UUID] = None
    protocol: str
    reason: str
    requested_duration: int
    status: str

    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: Optional[List[Dict[str, Any]]] = None

    policy_decision: Optional[Dict[str, Any]] = None
    policy_id: Optional[UUID] = None

    approval_required: bool
    jit_required: bool
    mfa_required: bool
    recording_required: bool

    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[UUID] = None


class JITGrantSummary(BaseModel):
    """The JIT grant issued for a request. `status` is EXPIRED once
    `expires_at` has passed, even before the stored row is flipped."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    protocol: str
    status: str
    granted_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None


class AccessRequestDetailOut(AccessRequestOut):
    jit_grant: Optional[JITGrantSummary] = None
