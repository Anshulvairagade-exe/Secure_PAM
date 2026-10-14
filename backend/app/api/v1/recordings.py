"""
Recordings API Router — M12 Session Recording & Evidence Access.

Recordings are evidence of other users' privileged sessions, so access is
limited to holders of recordings:read (AUDITOR, ADMIN); there is no
per-owner scope. Every playback is audited (RECORDING_VIEWED), and the
file served must resolve inside RECORDING_STORAGE_PATH — a tampered
file_path (absolute elsewhere, "..", or a symlink out) is treated as not
found rather than served.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
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
from app.services.command_transcript import transcript_path
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
    # verified: artifact present, matches its stored SHA-256 and (RDP) holds display frames;
    # no_display_data: hash matches but there is nothing to play; mismatch: it
    # does not; missing: COMPLETED but the artifact is gone; not_available:
    # no completed artifact exists.
    integrity: str = "not_available"
    # A derived activity transcript exists (recorded in metadata at capture time).
    transcript_available: bool = False
    # asciicast (SSH terminal) or guacamole (RDP screen); tells the UI which player to use.
    format: Optional[str] = None


def _resolve_inside_storage(file_path: str) -> Optional[Path]:
    """The first existing playable variant of file_path that resolves inside
    the storage root, or None."""
    from app.services.rdp_gateway import rdp_recording_root

    roots = (Path(settings.RECORDING_STORAGE_PATH).resolve(), rdp_recording_root())
    for suffix in _PLAYABLE_SUFFIXES:
        candidate = Path(f"{file_path}{suffix}").resolve()
        if any(candidate.is_relative_to(root) for root in roots) and candidate.is_file():
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
    if sha256_file(path) != recording.file_hash:
        return "mismatch"
    # A matching hash proves the bytes are unchanged, not that they are a usable screen recording.
    if (recording.metadata_ or {}).get("format") == "guacamole" and not _has_display_frames(path):
        return "no_display_data"
    return "verified"


def _has_display_frames(path: Path) -> bool:
    """A Guacamole recording that never drew a frame (e.g. only an error instruction) is not playable."""
    from app.services.guacamole import looks_like_recording
    try:
        with open(path, "rb") as handle:
            head = handle.read(65536)
            handle.seek(0)
            frames = any(b"4.sync," in block for block in iter(lambda: handle.read(1 << 20), b""))
    except OSError:
        return False
    return looks_like_recording(head) and frames


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
        item.transcript_available = bool((recording.metadata_ or {}).get("transcript"))
        item.format = (recording.metadata_ or {}).get("format") or (
            "asciicast" if recording.recording_type == "TERMINAL" else None)



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
    if (recording.metadata_ or {}).get("format") == "guacamole" and not _has_display_frames(valid_path):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Recording contains no display data and cannot be played")
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
    fmt = (recording.metadata_ or {}).get("format")
    media_type = ("application/x-asciicast" if recording.recording_type == "TERMINAL"
                  else "application/x-guacamole-recording" if fmt == "guacamole" else "video/mp4")
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if recording.file_hash:
        headers["X-Recording-SHA256"] = recording.file_hash
    return FileResponse(valid_path, media_type=media_type, headers=headers)


_RDP_TRANSCRIPT_REASON = (
    "Activity for Windows/RDP sessions needs endpoint telemetry (Security event 4688, PowerShell 4104, Sysmon), "
    "which is not integrated. Screen video alone does not show which commands were run."
)


async def _load_transcript(db: AsyncSession, recording_id: uuid.UUID, user: User, request: Request):
    """(recording, session, document-or-None, reason). Raises 404/409 for
    missing recordings and for a transcript that fails its integrity check."""
    recording = await db.get(Recording, recording_id)
    if not recording or recording.status == "DELETED":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recording not found")
    session = await db.get(Session, recording.session_id)
    if recording.recording_type != "TERMINAL":
        return recording, session, None, _RDP_TRANSCRIPT_REASON
    if recording.status != "COMPLETED":
        return recording, session, None, f"The recording is {recording.status}; no transcript was produced."
    meta = (recording.metadata_ or {}).get("transcript")
    if not meta:
        return recording, session, None, (
            "No transcript was captured for this recording (it predates transcripts or capture failed). "
            "The recording itself can still be replayed.")
    path = transcript_path(recording.file_path or "")
    root = Path(settings.RECORDING_STORAGE_PATH).resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return recording, session, None, "The transcript file is missing from storage."
    if sha256_file(resolved) != meta.get("sha256"):
        await write_audit_log(
            db, actor=user, action="TRANSCRIPT_INTEGRITY_FAILED", target_type="recording",
            target_id=str(recording.id), session_id=recording.session_id, source_ip=client_ip(request),
            result="FAILURE", severity="CRITICAL")
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "Transcript failed integrity verification and was not served")
    return recording, session, resolved, None


@router.get("/{recording_id}/transcript")
async def get_transcript(
    recording_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("recordings", "read")),
):
    """Activity transcript: typed input lines with the output that followed,
    timed against the recording. Observed input, not proof of execution."""
    recording, session, path, reason = await _load_transcript(db, recording_id, current_user, request)
    body = {"available": path is not None, "reason": reason, "recording_id": str(recording.id),
            "session_number": session.session_number if session else None, "transcript": None}
    if path is not None:
        body["transcript"] = json.loads(path.read_text(encoding="utf-8"))
        await write_audit_log(
            db, actor=current_user, action="TRANSCRIPT_VIEWED", target_type="recording",
            target_id=str(recording.id), session_id=recording.session_id, source_ip=client_ip(request),
            result="SUCCESS", severity="INFO")
        await db.commit()
    return JSONResponse(body, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/{recording_id}/transcript/export")
async def export_transcript(
    recording_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("recordings", "download")),
):
    recording, session, path, reason = await _load_transcript(db, recording_id, current_user, request)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, reason)
    await write_audit_log(
        db, actor=current_user, action="TRANSCRIPT_EXPORTED", target_type="recording",
        target_id=str(recording.id), session_id=recording.session_id, source_ip=client_ip(request),
        result="SUCCESS", severity="MEDIUM")
    await db.commit()
    name = f"{session.session_number if session else recording.id}-transcript.json"
    return FileResponse(path, media_type="application/json", filename=name,
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
