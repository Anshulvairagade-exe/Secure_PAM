"""
RDP screen recording: guacd writes the raw Guacamole instruction stream to a
per-session directory (recording-path/recording-name connection parameters);
this module decides, from what is actually on disk, whether the recording is
real.

A recording is COMPLETED only when the file exists inside the RDP recording
root, is non-empty, is a well-formed Guacamole stream, and has been hashed
after guacd closed it. Anything else is FAILED, with the reason audited. The
artifact is never served by path: the recordings API verifies the stored
SHA-256 on every playback.
"""

import asyncio
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.audit import write_audit_log
from app.database.session import async_session_factory
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.services.guacamole import looks_like_recording, recording_duration_seconds
from app.services.rdp_gateway import rdp_recording_root
from app.services.terminal_recorder import sha256_file

RECORDING_NAME = "recording"
SETTLE_SECONDS = 25.0


def session_recording_dir(session_id: uuid.UUID) -> Path:
    return rdp_recording_root() / str(session_id)


def session_recording_file(session_id: uuid.UUID) -> Path:
    return session_recording_dir(session_id) / RECORDING_NAME


def _inside_root(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(rdp_recording_root())
    except OSError:
        return False


async def wait_for_recording_file(session_id: uuid.UUID, timeout: float = 5.0) -> bool:
    """guacd creates the file as the connection starts. True once it exists."""
    path = session_recording_file(session_id)
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if _inside_root(path) and path.is_file():
            return True
        await asyncio.sleep(0.2)
    return False


QUIET_SECONDS = 3.0


def _fingerprint(path: Path):
    try:
        st = path.stat()
        return st.st_size, st.st_mtime_ns
    except OSError:
        return None


async def _wait_until_quiet(path: Path, timeout: float, quiet: float = QUIET_SECONDS) -> None:
    """guacd flushes and closes its recording shortly after the client disconnects, and offers no signal
    we can rely on. The artifact is final only once its size and mtime have not changed for `quiet`
    seconds (bounded by `timeout`)."""
    if timeout <= 0:
        return
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    last, since = _fingerprint(path), loop.time()
    while loop.time() < deadline:
        await asyncio.sleep(0.5)
        now = _fingerprint(path)
        if now != last:
            last, since = now, loop.time()
        elif now is not None and now[0] > 0 and loop.time() - since >= quiet:
            return


def _inspect(path: Path):
    """(sha256, size, duration, head_ok) of a finalized artifact; raises OSError if unreadable."""
    size = path.stat().st_size
    with open(path, "rb") as handle:
        head = handle.read(65536)
        handle.seek(max(0, size - 65536))
        tail = handle.read(65536)
    has_frames = b"4.sync," in head or b"4.sync," in tail
    return sha256_file(path), size, recording_duration_seconds(head, tail), looks_like_recording(head), has_frames


async def finalize_rdp_recording(
    recording_id: uuid.UUID, session_id: uuid.UUID, actor_id: uuid.UUID, *, failure_reason: Optional[str] = None,
    settle_seconds: float = SETTLE_SECONDS,
) -> str:
    """Settle the recording by what exists. Returns the final status."""
    path = session_recording_file(session_id)
    reason = failure_reason
    result = None
    if reason is None:
        if not (_inside_root(path) and path.is_file()):
            reason = "RECORDING_ARTIFACT_MISSING"
        else:
            await _wait_until_quiet(path, settle_seconds)
            try:
                before = _fingerprint(path)
                digest, size, duration, well_formed, has_frames = await asyncio.to_thread(_inspect, path)
                if settle_seconds > 0 and _fingerprint(path) != before:
                    # Changed while hashing: not final yet. Settle again and re-hash once.
                    await _wait_until_quiet(path, settle_seconds)
                    digest, size, duration, well_formed, has_frames = await asyncio.to_thread(_inspect, path)
                if size == 0:
                    reason = "RECORDING_EMPTY"
                elif not well_formed:
                    reason = "RECORDING_CORRUPT"
                elif not has_frames:
                    reason = "RECORDING_NO_FRAMES"  # e.g. only an error instruction: nothing was on screen
                else:
                    result = (digest, size, duration)
                    for target, mode in ((path, 0o640), (path.parent, 0o750)):
                        try:
                            os.chmod(target, mode)
                        except OSError:
                            pass
            except OSError:
                reason = "RECORDING_UNREADABLE"

    async with async_session_factory() as db:
        rec = await db.get(Recording, recording_id)
        actor = await db.get(User, actor_id)
        if rec is None:
            return "FAILED"
        if result is not None:
            digest, size, duration = result
            # A static desktop sends few frames, so the stream alone can undercount a long session:
            # report the longer of the stream length and the session's connected time.
            session = await db.get(Session, session_id)
            if session is not None and session.start_time is not None:
                connected = int((datetime.now(timezone.utc) - session.start_time).total_seconds())
                duration = max(duration or 0, connected)
            rec.status, rec.file_hash, rec.file_size, rec.duration_seconds = "COMPLETED", digest, size, duration
            rec.metadata_ = {**(rec.metadata_ or {}), "format": "guacamole"}
            action, outcome, severity = "RECORDING_COMPLETED", "SUCCESS", "INFO"
            details = {"sha256": digest, "file_size": size, "duration_seconds": duration, "format": "guacamole"}
        else:
            rec.status = "FAILED"
            action, outcome, severity = "RECORDING_FAILED", "FAILURE", "HIGH"
            details = {"reason": reason}
        await write_audit_log(
            db, actor=actor, action=action, target_type="recording", target_id=str(rec.id), session_id=session_id,
            result=outcome, severity=severity, metadata=details,
        )
        await db.commit()
        return rec.status
