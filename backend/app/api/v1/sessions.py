"""
Sessions API Router — M9 RDP Gateway & Session Orchestration.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database.session import get_db
from app.models.session import Session, SessionEvent
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.recording import Recording
from app.core.config import settings

router = APIRouter(prefix="/sessions", tags=["Sessions"])


class CreateRDPSessionRequest(BaseModel):
    request_id: uuid.UUID
    asset_id: uuid.UUID


class SessionResponse(BaseModel):
    id: uuid.UUID
    session_number: str
    user_id: uuid.UUID
    asset_id: Optional[uuid.UUID]
    protocol: str
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    recording_id: Optional[uuid.UUID]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[SessionResponse])
async def list_sessions(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db)
):
    """List sessions, optionally filtered by status (ACTIVE, COMPLETED, etc.)."""
    query = select(Session).order_by(Session.created_at.desc())
    if status_filter:
        query = query.where(Session.status == status_filter.upper())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Retrieve details for a single session."""
    session = await db.get(Session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/rdp/launch")
async def launch_rdp_session(
    payload: CreateRDPSessionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Launch an RDP session via Guacamole.
    Generates session tracking, recording container hooks, and audit records.
    """
    # 1. Fetch target asset
    asset = await db.get(Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Target asset not found")

    session_id = uuid.uuid4()
    session_num = f"SES-{uuid.uuid4().hex[:6].upper()}"
    recording_name = f"session_{session_id}"

    # 2. Register Recording metadata placeholder (M12)
    recording = Recording(
        id=uuid.uuid4(),
        session_id=session_id,
        recording_type="VIDEO",
        status="RECORDING",
        file_path=f"{settings.RECORDING_STORAGE_PATH}/{recording_name}"
    )
    db.add(recording)

    # 3. Create Session entry
    new_session = Session(
        id=session_id,
        session_number=session_num,
        user_id=uuid.uuid4(), # Replace with current_user.id when auth dependency is integrated
        asset_id=payload.asset_id,
        request_id=payload.request_id,
        protocol="RDP",
        status="ACTIVE",
        recording_id=recording.id,
        start_time=datetime.now(timezone.utc)
    )
    db.add(new_session)

    # 4. Create Session Event & Audit Log
    event = SessionEvent(
        session_id=session_id,
        event_type="SESSION_CREATED",
        timestamp=datetime.now(timezone.utc),
        details={"protocol": "RDP", "recording": True}
    )
    audit = AuditLog(
        event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        actor_username="admin", # Replace with current_user.username
        action="SESSION_STARTED",
        target_type="asset",
        target_id=str(asset.id),
        session_id=session_id,
        request_id=payload.request_id,
        result="SUCCESS",
        severity="INFO",
        details={"protocol": "RDP", "session_number": session_num}
    )
    db.add(event)
    db.add(audit)
    await db.commit()

    # 5. Return connection parameters for Guacamole client
    return {
        "session_id": str(session_id),
        "session_number": session_num,
        "guacamole_connection": {
            "protocol": "rdp",
            "hostname": asset.address,
            "port": asset.port or 3389,
            "recording_path": settings.RECORDING_STORAGE_PATH,
            "recording_name": recording_name
        }
    }


@router.post("/{session_id}/terminate")
async def terminate_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Terminate an active session and finalize audit records."""
    session = await db.get(Session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session.status = "COMPLETED"
    session.end_time = datetime.now(timezone.utc)

    # Update recording status
    if session.recording_id:
        recording = await db.get(Recording, session.recording_id)
        if recording:
            recording.status = "COMPLETED"

    # Audit the termination
    audit = AuditLog(
        event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        actor_username="admin",
        action="SESSION_TERMINATED",
        target_type="session",
        target_id=str(session.id),
        session_id=session.id,
        result="SUCCESS",
        severity="INFO"
    )
    db.add(audit)
    await db.commit()

    return {"message": "Session terminated successfully", "session_id": str(session_id)}