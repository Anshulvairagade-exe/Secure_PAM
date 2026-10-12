"""
Audit API Router — M12 Structured Audit Logs & SIEM Export.
"""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database.session import get_db
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit", tags=["Audit"])


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    event_id: str
    timestamp: datetime
    actor_username: str
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    result: str
    severity: str
    details: Optional[dict]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[AuditLogResponse])
async def get_audit_logs(
    action: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve recent structured audit logs with optional filtering."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if action:
        query = query.where(AuditLog.action == action.upper())
    if severity:
        query = query.where(AuditLog.severity == severity.upper())

    result = await db.execute(query)
    return result.scalars().all()