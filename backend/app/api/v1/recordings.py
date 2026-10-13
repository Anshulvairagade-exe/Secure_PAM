"""
Recordings API Router — M12 Session Recording & Evidence Access.

Recordings are evidence of other users' privileged sessions, so access is
limited to holders of recordings:read (AUDITOR, ADMIN); there is no
per-owner scope. Every playback is audited (RECORDING_VIEWED), and the
file served must resolve inside RECORDING_STORAGE_PATH — a tampered
file_path (absolute elsewhere, "..", or a symlink out) is treated as not
found rather than served.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict

from app.core.pagination import apply_sorting, paginate
from app.schemas.common import PaginatedResponse, PaginationParams
from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db
from app.models.asset import Asset
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.services.terminal_recorder import sha256_file

router = APIRouter(prefix="/recordings", tags=["Recordings"])
_SORTABLE_COLUMNS = {
    "created_at",
    "file_size",
    "duration_seconds",
    "status",
    "recording_type",
}
_PLAYABLE_SUFFIXES = ("", ".m4v", ".mp4")


class RecordingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    recording_type: str
    status: str
    file_size: Optional[int]
    duration_seconds: Optional[int]
    created_at: datetime
    # Context (never the storage path).
    session_number: Optional[str] = None
    operator_username: Optional[str] = None
    asset_name: Optional[str] = None
    protocol: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    sha256: Optional[str] = None
    # verified: artifact present and matches its stored SHA-256; mismatch: it
    # does not; missing: COMPLETED but the artifact is gone; not_available:
    # no completed artifact exists.
    integrity: str = "not_available"


def _resolve_inside_storage(file_path: str) -> Optional[Path]:
    """The first existing playable variant of file_path that resolves inside
    the storage root, or None."""
    root = Path(settings.RECORDING_STORAGE_PATH).resolve()
    for suffix in _PLAYABLE_SUFFIXES:
        candidate = Path(f"{file_path}{suffix}").resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return candidate
    return None



@router.get("/", response_model=PaginatedResponse[RecordingResponse])
async def list_recordings(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("recordings", "read")),
):
    """List recordings with pagination and allowlisted sorting."""
    query = select(Recording)

    query = apply_sorting(
        query,
        Recording,
        pagination.sort_by,
        pagination.sort_order,
        _SORTABLE_COLUMNS,
    )

    # Preserve newest-first ordering by default.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(Recording.created_at.desc())

    page = await paginate(db, query, pagination, schema=RecordingResponse)
    await _enrich(db, page.items)
    return page


def _integrity(recording: Recording) -> str:
    if recording.status != "COMPLETED" or not recording.file_hash or not recording.file_path:
        return "not_available"
    path = _resolve_inside_storage(recording.file_path)
    if path is None:
        return "missing"
    return "verified" if sha256_file(path) == recording.file_hash else "mismatch"


async def _enrich(db: AsyncSession, items: List[RecordingResponse]) -> None:
    for item in items:
        recording = await db.get(Recording, item.id)
        session = await db.get(Session, item.session_id)
        if session is not None:
            operator = await db.get(User, session.user_id)
            asset = await db.get(Asset, session.asset_id) if session.asset_id else None
            item.session_number = session.session_number
            item.operator_username = operator.username if operator else None
            item.asset_name = asset.name if asset else None
            item.protocol = session.protocol
            item.started_at = session.start_time
            item.ended_at = session.end_time
        item.sha256 = recording.file_hash
        item.integrity = _integrity(recording)



@router.get("/{recording_id}/stream")
async def stream_recording(
    recording_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("recordings", "read")),
):
    """Stream a session recording file for browser playback."""
    recording = await db.get(Recording, recording_id)
    if not recording or not recording.file_path or recording.status == "DELETED":
        raise HTTPException(status_code=404, detail="Recording not found")

    if recording.status != "COMPLETED":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Recording is {recording.status}; only completed recordings can be played")
    valid_path = _resolve_inside_storage(recording.file_path)
    if not valid_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording video file not yet processed or not found on disk",
        )
    # Verify integrity before serving evidence.
    if recording.file_hash and sha256_file(valid_path) != recording.file_hash:
        await write_audit_log(
            db, actor=current_user, action="RECORDING_INTEGRITY_FAILED", target_type="recording",
            target_id=str(recording.id), session_id=recording.session_id,
            source_ip=client_ip(request), result="FAILURE", severity="CRITICAL",
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Recording failed integrity verification and was not served")

    await write_audit_log(
        db, actor=current_user, action="RECORDING_VIEWED", target_type="recording",
        target_id=str(recording.id), session_id=recording.session_id,
        source_ip=client_ip(request), result="SUCCESS", severity="INFO",
    )
    await db.commit()
    media_type = "application/x-asciicast" if recording.recording_type == "TERMINAL" else "video/mp4"
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if recording.file_hash:
        headers["X-Recording-SHA256"] = recording.file_hash
    return FileResponse(valid_path, media_type=media_type, headers=headers)
