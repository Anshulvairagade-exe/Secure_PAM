"""
Terminate privileged sessions for real, and say honestly what happened.

Order of operations for one session:
  1. TERMINATING is committed. The SSH monitor re-reads the session row every
     second (on whichever worker holds the terminal) and closes the transport.
  2. If this process holds the connection, wait until its owner has closed it (confirmed from the registry).
  3. The recording is settled by what actually exists: the gateway finalizes
     (closes and hashes) a live recorder; a recording that never started, or
     whose finalization did not happen, is FAILED. Never COMPLETED by assertion.
  4. Only then is the session marked TERMINATED (or COMPLETED when the owner
     ends their own session) and, for an admin action, the bound JIT grant
     revoked so the same grant cannot start another session.
If the gateway cannot be closed the session stays TERMINATING and the result
says so; nothing is marked terminated that is not.
"""

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.jit_service import JITService
from app.services.ssh_terminal_gateway import AsyncSSHTerminalGateway

logger = logging.getLogger("securepam.termination")

LIVE_STATUSES = ("CREATED", "STARTING", "ACTIVE", "TERMINATING")
# An RDP recording is final only after its file has been quiet for a few seconds (rdp_recording), so
# this outlasts that; the wait ends as soon as the gateway reports the recording's final state.
SETTLE_SECONDS = 30.0
GATEWAY_WAIT_SECONDS = 8.0  # the monitor polls every second


@dataclass
class TerminationResult:
    session_id: str
    session_number: str
    ok: bool
    status: str
    gateway: str = "not_connected"  # closed | not_connected | delegated | failed
    recording: Optional[str] = None
    grant_revoked: Optional[bool] = None
    errors: List[str] = field(default_factory=list)

    def dict(self) -> dict:
        return asdict(self)


async def _close_gateway(session: Session, gateway) -> tuple[str, Optional[str]]:
    """The connection's owner (the websocket handler that holds it) closes it as soon as its monitor sees
    TERMINATING, on its own event loop. We never reach into another loop's transport; we wait for the
    connection to leave the registry and report what we saw."""
    if gateway is None or not hasattr(gateway, "get_live_connection"):
        return "not_connected", None
    live = gateway.get_live_connection(session.id)
    if live is not None and getattr(live, "attached", True) is False:
        # An isolated browser that no operator is connected to: nothing else will stop it, so stop it here.
        # (A daemon API call, not a foreign event loop's transport.)
        try:
            await gateway.close_connection(session.id)
        except Exception as exc:
            return "failed", f"The isolated browser could not be stopped ({type(exc).__name__})."
        return ("closed", None) if gateway.get_live_connection(session.id) is None else \
            ("failed", "The isolated browser is still registered after stop.")
    if live is None:
        # Not held by this process: never connected, or on another worker where its monitor acts.
        return ("delegated" if session.status in ("ACTIVE", "TERMINATING") else "not_connected"), None
    loop = asyncio.get_event_loop()
    deadline = loop.time() + GATEWAY_WAIT_SECONDS
    while loop.time() < deadline:
        await asyncio.sleep(0.1)
        if gateway.get_live_connection(session.id) is None:
            return "closed", None
    logger.error("gateway connection still registered after %.0fs session=%s", GATEWAY_WAIT_SECONDS, session.id)
    return "failed", "The gateway connection was still open after the termination signal."


async def _settle_recording(db: AsyncSession, session: Session, actor: User, gateway_state: str) -> Optional[str]:
    if not session.recording_id:
        return None
    recording = await db.get(Recording, session.recording_id)
    if recording is None:
        return None
    deadline = asyncio.get_event_loop().time() + SETTLE_SECONDS
    while recording.status == "RECORDING" and gateway_state in ("closed", "delegated") \
            and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.25)
        await db.refresh(recording)  # the gateway finalizes from its own transaction
    if recording.status in ("PENDING", "RECORDING"):
        reason = "RECORDING_NOT_STARTED" if recording.status == "PENDING" else "RECORDING_NOT_FINALIZED"
        recording.status = "FAILED"
        await write_audit_log(
            db, actor=actor, action="RECORDING_FAILED", target_type="recording", target_id=str(recording.id),
            session_id=session.id, result="FAILURE", severity="HIGH", metadata={"reason": reason},
        )
    return recording.status


async def terminate_session(
    db: AsyncSession,
    session: Session,
    *,
    actor: User,
    source_ip: Optional[str],
    gateway: Optional[AsyncSSHTerminalGateway],
    rdp_gateway=None,
    web_gateway=None,
    reason: Optional[str] = None,
    revoke_grant: bool = False,
    final_status: str = "TERMINATED",
) -> TerminationResult:
    result = TerminationResult(str(session.id), session.session_number, ok=False, status=session.status)
    by_owner = session.user_id == actor.id
    now = datetime.now(timezone.utc)

    session.status = "TERMINATING"
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_TERMINATING", timestamp=now,
                        details={"by_owner": by_owner, "reason": reason}))
    await db.commit()

    result.gateway, error = await _close_gateway(
        session, rdp_gateway if session.protocol == "RDP" else web_gateway if session.protocol in ("HTTP", "HTTPS") else gateway)
    if error:
        result.status = "TERMINATING"
        result.errors.append(error)
        await write_audit_log(
            db, actor=actor, action="SESSION_TERMINATION_FAILED", target_type="session", target_id=str(session.id),
            request_id=session.request_id, session_id=session.id, source_ip=source_ip, result="FAILURE",
            severity="HIGH", metadata={"reason": reason, "gateway": result.gateway, "error": error},
        )
        await db.commit()
        return result

    result.recording = await _settle_recording(db, session, actor, result.gateway)
    await db.refresh(session)  # the gateway may have recorded its own close meanwhile
    end = datetime.now(timezone.utc)
    session.status, session.end_time = final_status, end
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_TERMINATED", timestamp=end,
                        details={"by_owner": by_owner, "reason": reason, "gateway": result.gateway}))
    result.status = final_status

    if revoke_grant and session.jit_grant_id:
        grant = await db.get(JITGrant, session.jit_grant_id)
        try:
            if grant is not None:
                await JITService().revoke(db, grant)
            result.grant_revoked = grant is not None and grant.status == "REVOKED"
            await write_audit_log(
                db, actor=actor, action="JIT_REVOKED", target_type="jit_grant", target_id=str(session.jit_grant_id),
                request_id=session.request_id, session_id=session.id, source_ip=source_ip, result="SUCCESS",
                severity="HIGH", metadata={"reason": reason or "session terminated by administrator",
                                           "grantee_user_id": str(session.user_id)},
            )
        except Exception as exc:
            result.grant_revoked = False
            result.errors.append(f"The JIT grant could not be revoked ({type(exc).__name__}).")

    await write_audit_log(
        db, actor=actor, action="SESSION_TERMINATED", target_type="session", target_id=str(session.id),
        request_id=session.request_id, session_id=session.id, source_ip=source_ip, result="SUCCESS",
        severity="INFO" if by_owner else "HIGH",
        metadata={"by_owner": by_owner, "reason": reason, "gateway": result.gateway,
                  "recording": result.recording, "grant_revoked": result.grant_revoked,
                  "affected_user_id": str(session.user_id)},
    )
    await db.commit()
    result.ok = not result.errors
    return result
