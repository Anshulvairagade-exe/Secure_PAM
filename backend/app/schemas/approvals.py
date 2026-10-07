"""Approval schemas. approver_id/status/decided_at are always server-set."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_id: UUID
    approver_id: Optional[UUID] = None
    status: str
    comment: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime


class ApproveInput(BaseModel):
    comment: Optional[str] = Field(default=None, max_length=2000)


class RejectInput(BaseModel):
    # A rejection reason is mandatory — approving silently is fine,
    # rejecting without explanation is not (Phase 4 spec, section 14).
    comment: str = Field(min_length=1, max_length=2000)
