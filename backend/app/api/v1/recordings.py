"""
Recordings API Router — M12 Session Recording & Evidence Access.
"""

import os
import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database.session import get_db
from app.models.recording import Recording
from app.core.config import settings

router = APIRouter(prefix="/recordings", tags=["Recordings"])


class RecordingResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    recording_type: str
    status: str
    file_size: Optional[int]
    duration_seconds: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[RecordingResponse])
async def list_recordings(db: AsyncSession = Depends(get_db)):
    """List all available session recordings."""
    query = select(Recording).order_by(Recording.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{recording_id}/stream")
async def stream_recording(recording_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Stream a session recording file for browser playback.
    """
    recording = await db.get(Recording, recording_id)
    if not recording or not recording.file_path:
        raise HTTPException(status_code=404, detail="Recording not found")

    file_path = recording.file_path
    # Check both direct file and .m4v/.mp4 transcoded versions
    possible_paths = [file_path, f"{file_path}.m4v", f"{file_path}.mp4"]
    valid_path = next((p for p in possible_paths if os.path.exists(p)), None)

    if not valid_path:
        raise HTTPException(
            status_code=404,
            detail="Recording video file not yet processed or not found on disk"
        )

    return FileResponse(valid_path, media_type="video/mp4")