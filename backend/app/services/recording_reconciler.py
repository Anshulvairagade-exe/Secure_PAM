"""
Settle recordings that nothing will ever finalize.

A recording becomes COMPLETED only when its gateway closes and hashes the artifact. When a session ends
some other way (its JIT grant is revoked or expires, the worker holding the terminal dies, a browser
never connects), the gateway that owned the recorder may still finalize it within a few seconds, so
the session-ending code must not decide. This reconciler does, afterwards: a recording still PENDING
or RECORDING whose session ended more than GRACE_SECONDS ago is FAILED, with an audited reason.
It never marks anything COMPLETED.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.models.recording import Recording
from app.models.session import Session

# Longer than session_termination.SETTLE_SECONDS (30 s) and the RDP quiet period, so a gateway that is
# finalizing always wins the race.
GRACE_SECONDS = 120
ENDED_SESSION_STATUSES = ("COMPLETED", "TERMINATED", "EXPIRED", "FAILED")


async def reconcile_stale_recordings(
    db: AsyncSession, *, grace_seconds: int = GRACE_SECONDS, now: Optional[datetime] = None
) -> List[str]:
    """FAIL unfinalized recordings of sessions that ended before the grace window. Returns their ids."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=grace_seconds)
    rows = (await db.execute(
        select(Recording, Session)
        .join(Session, Session.id == Recording.session_id)
        .where(
            Recording.status.in_(("PENDING", "RECORDING")),
            Session.status.in_(ENDED_SESSION_STATUSES),
            Session.end_time.is_not(None),
            Session.end_time < cutoff,
        )
    )).all()
    failed: List[str] = []
    for recording, session in rows:
        reason = "RECORDING_NOT_STARTED" if recording.status == "PENDING" else "RECORDING_NOT_FINALIZED"
        recording.status = "FAILED"
        await write_audit_log(
            db, actor=None, action="RECORDING_FAILED", target_type="recording", target_id=str(recording.id),
            session_id=session.id, result="FAILURE", severity="HIGH",
            metadata={"reason": reason, "session_status": session.status, "settled_by": "reconciler",
                      "grace_seconds": grace_seconds},
        )
        failed.append(str(recording.id))
    if failed:
        await db.commit()
    return failed
