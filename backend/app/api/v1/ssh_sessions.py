"""
SSH Sessions API Router — Member 10 SSH Gateway Launch & Orchestration.

Authorization & Lifecycle:
- SSH launch: caller holds sessions:create permission, an active access request
  for that SSH asset, an active JIT grant from JITService.validate() bound to that
  request, and a CredentialService checkout bound to the new session.
- Any failure marks the session FAILED; nothing is reported as started.
- Response never contains credentials, private keys, or internal filesystem paths.
- With a placeholder gateway (upstream transport not yet connected), the session
  remains in 'STARTING' status and recording in 'PENDING' status, truthfully
  reflecting that the upstream connection has not yet been established.
"""

import asyncio
import json
import logging
import uuid
import anyio
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db
from app.core.security import generate_session_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.database.session import async_session_factory
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)
from app.services.jit_service import JITService
from app.services.ssh_gateway import SSHError, SSHGateway, get_ssh_gateway
from app.services.ssh_terminal_gateway import (
    AsyncSSHTerminalGateway,
    MAX_TERMINAL_CHUNK_SIZE,
    get_terminal_gateway,
)
from app.services.ssh_ticket import (
    SSHTicketInvalidError,
    SSHTicketService,
    SSHTicketStorageError,
    get_ssh_ticket_service,
)

router = APIRouter(prefix="/sessions", tags=["SSH Sessions"])
logger = logging.getLogger("securepam.ssh")

_jit = JITService()


def get_credential_service() -> CredentialService:
    return CredentialService()


class CreateSSHSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: uuid.UUID
    asset_id: uuid.UUID


async def _fail_launch(
    db: AsyncSession,
    *,
    session: Session,
    recording: Optional[Recording],
    actor: User,
    reason: str,
    source_ip: Optional[str],
) -> None:
    now = datetime.now(timezone.utc)
    session.status = "FAILED"
    session.end_time = now
    if recording:
        recording.status = "FAILED"
    db.add(
        SessionEvent(
            session_id=session.id,
            event_type="SESSION_FAILED",
            timestamp=now,
            details={"reason": reason},
        )
    )
    await write_audit_log(
        db,
        actor=actor,
        action="SESSION_LAUNCH_FAILED",
        target_type="asset",
        target_id=str(session.asset_id),
        request_id=session.request_id,
        session_id=session.id,
        source_ip=source_ip,
        result="FAILURE",
        severity="HIGH",
        metadata={"reason": reason, "protocol": session.protocol},
    )
    await db.commit()


@router.post("/ssh/launch", status_code=status.HTTP_201_CREATED)
async def launch_ssh_session(
    payload: CreateSSHSessionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "create")),
    credentials: CredentialService = Depends(get_credential_service),
    gateway: SSHGateway = Depends(get_ssh_gateway),
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
):
    """
    Launch an SSH session via the SSH gateway seam.
    Validates RBAC, asset, access request, and JIT grant.
    Checks out credentials securely in-memory and hands them only to the gateway.
    Never exposes secrets in responses or logs.
    """
    source_ip = client_ip(request)

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == payload.asset_id, Asset.is_deleted == False)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target asset not found")

    access_request = await db.get(AccessRequest, payload.request_id)
    if access_request is None or access_request.user_id != current_user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")
    if access_request.asset_id != asset.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Access request is for a different target")
    if asset.protocol != "SSH" or access_request.protocol != "SSH":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target and request must both be SSH")

    async def deny(reason: str, detail: str):
        await write_audit_log(
            db,
            actor=current_user,
            action="SESSION_LAUNCH_DENIED",
            target_type="asset",
            target_id=str(asset.id),
            request_id=access_request.id,
            source_ip=source_ip,
            result="DENIED",
            severity="MEDIUM",
            metadata={"reason": reason, "protocol": "SSH"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)

    if not asset.enabled or asset.status != "ACTIVE":
        await deny("ASSET_DISABLED", "This target is not available.")
    if access_request.status != "ACTIVE":
        await deny("ACCESS_REQUEST_NOT_ACTIVE", "This access request is not active.")

    grant = await _jit.validate(db, user_id=current_user.id, target_id=asset.id, protocol="SSH")
    if grant is None or grant.request_id != access_request.id:
        await deny("NO_VALID_JIT_GRANT", "No valid just-in-time grant for this request.")

    session = Session(
        session_number=generate_session_number(),
        user_id=current_user.id,
        asset_id=asset.id,
        request_id=access_request.id,
        jit_grant_id=grant.id,
        protocol="SSH",
        status="STARTING",
        source_ip=source_ip,
        risk_score=access_request.risk_score,
    )
    db.add(session)
    await db.flush()

    recording: Optional[Recording] = None
    if asset.recording_required or access_request.recording_required:
        recording = Recording(
            session_id=session.id,
            recording_type="TERMINAL",
            status="PENDING",
            file_path=f"{settings.RECORDING_STORAGE_PATH}/session_{session.id}.cast",
        )
        db.add(recording)
        await db.flush()
        session.recording_id = recording.id

    db.add(
        SessionEvent(
            session_id=session.id,
            event_type="SESSION_CREATED",
            timestamp=datetime.now(timezone.utc),
            details={"protocol": "SSH"},
        )
    )
    await db.commit()

    checkout = CheckoutRequest(
        user_id=current_user.id,
        access_request_id=access_request.id,
        jit_grant_id=grant.id,
        asset_id=asset.id,
        session_id=session.id,
        source_ip=source_ip,
    )

    try:
        try:
            async with credentials.checkout(db, checkout) as credential:
                connection = await gateway.prepare(session=session, asset=asset, credential=credential)
        except CredentialAccessDenied as exc:
            await _fail_launch(
                db,
                session=session,
                recording=recording,
                actor=current_user,
                reason=exc.reason,
                source_ip=source_ip,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Credential access was denied for this session.")
        except CredentialUnavailable as exc:
            await _fail_launch(
                db,
                session=session,
                recording=recording,
                actor=current_user,
                reason=exc.reason,
                source_ip=source_ip,
            )
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "Credential provider unavailable; session not started."
            )
        except SSHError:
            await _fail_launch(
                db,
                session=session,
                recording=recording,
                actor=current_user,
                reason="GATEWAY_ERROR",
                source_ip=source_ip,
            )
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "SSH gateway could not start the session.")

        now = datetime.now(timezone.utc)
        session.gateway_session_id = connection.gateway_session_id

        if connection.is_connected:
            # A live upstream SSH connection was established
            session.status = "ACTIVE"
            session.start_time = now
            if recording:
                # Truthful recording status: Member 10 does not yet capture terminal streams;
                # keep status PENDING rather than falsely asserting RECORDING.
                recording.status = "PENDING"
            db.add(
                SessionEvent(
                    session_id=session.id,
                    event_type="SESSION_STARTED",
                    timestamp=now,
                    details={"protocol": "SSH", "recording": recording is not None},
                )
            )
            await write_audit_log(
                db,
                actor=current_user,
                action="SESSION_STARTED",
                target_type="asset",
                target_id=str(asset.id),
                request_id=access_request.id,
                session_id=session.id,
                source_ip=source_ip,
                result="SUCCESS",
                severity="INFO",
                metadata={
                    "protocol": "SSH",
                    "session_number": session.session_number,
                    "jit_grant_id": str(grant.id),
                    "recording": recording is not None,
                },
            )
        else:
            # Placeholder or pending gateway — prepared but not yet connected live
            session.status = "STARTING"
            if recording:
                recording.status = "PENDING"
            db.add(
                SessionEvent(
                    session_id=session.id,
                    event_type="SESSION_PREPARED",
                    timestamp=now,
                    details={"protocol": "SSH", "pending_connection": True},
                )
            )
            await write_audit_log(
                db,
                actor=current_user,
                action="SESSION_PREPARED",
                target_type="asset",
                target_id=str(asset.id),
                request_id=access_request.id,
                session_id=session.id,
                source_ip=source_ip,
                result="SUCCESS",
                severity="INFO",
                metadata={
                    "protocol": "SSH",
                    "session_number": session.session_number,
                    "jit_grant_id": str(grant.id),
                    "status": "STARTING",
                },
            )

        await db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during SSH session launch: %s", exc)
        try:
            await _fail_launch(
                db,
                session=session,
                recording=recording,
                actor=current_user,
                reason="UNEXPECTED_LAUNCH_ERROR",
                source_ip=source_ip,
            )
        except Exception as fail_err:
            logger.exception("Failed to record launch failure state: %s", fail_err)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "An unexpected error occurred while launching the SSH session.",
        ) from exc

    # Issue single-use, 60-second connection ticket bound to this session
    ticket: Optional[str] = None
    try:
        ticket = await ticket_service.issue_ticket(
            session_id=session.id,
            user_id=current_user.id,
            asset_id=asset.id,
            access_request_id=access_request.id,
            jit_grant_id=grant.id,
            ttl_seconds=60,
        )
    except Exception as exc:
        logger.error("Failed to issue SSH connection ticket: %s", exc)
        await _fail_launch(
            db,
            session=session,
            recording=recording,
            actor=current_user,
            reason="TICKET_GENERATION_FAILED",
            source_ip=source_ip,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Failed to issue session connection ticket.",
        ) from exc

    ws_url = f"/api/v1/sessions/ssh/{session.id}/ws"

    return {
        "session_id": str(session.id),
        "session_number": session.session_number,
        "status": session.status,
        "recording_id": str(recording.id) if recording else None,
        "ticket": ticket,
        "ws_url": ws_url,
        "connection": {
            "mode": "GATEWAY_MEDIATED",
            "protocol": connection.protocol,
            "target_asset": asset.name,
            "target_host": connection.hostname,
            "target_port": connection.port,
            "gateway_session_id": connection.gateway_session_id,
            "is_connected": connection.is_connected,
            "direct_access_allowed": False,
            "ticket": ticket,
            "ws_url": ws_url,
            "message": (
                "SSH session connected via SecurePAM Gateway."
                if connection.is_connected
                else "SSH session prepared. Access must be routed through the SecurePAM Gateway; direct connections to the target are not permitted."
            ),
        },
    }


# --- Terminal Sizing Constants ---
DEFAULT_COLS = 80
DEFAULT_ROWS = 24
MIN_COLS = 10
MAX_COLS = 512
MIN_ROWS = 2
MAX_ROWS = 256


async def _close_session_in_db(
    session_id: uuid.UUID,
    *,
    status_val: str = "COMPLETED",
    reason: Optional[str] = None,
) -> None:
    """Safely record session termination in database using a short-lived session."""
    now = datetime.now(timezone.utc)
    try:
        async with async_session_factory() as db:
            session = await db.get(Session, session_id)
            if session and session.status not in ("COMPLETED", "FAILED", "EXPIRED"):
                session.status = status_val
                session.end_time = now
                if session.recording_id:
                    rec = await db.get(Recording, session.recording_id)
                    if rec:
                        # Truthful recording status: since Member 12 terminal stream capture
                        # is not yet implemented, recording cannot be marked COMPLETED.
                        # It is marked FAILED to avoid false audit assurance.
                        rec.status = "FAILED"
                event_name = (
                    "SESSION_EXPIRED"
                    if status_val == "EXPIRED"
                    else ("SESSION_CLOSED" if status_val == "COMPLETED" else "SESSION_FAILED")
                )
                if reason == "JIT_GRANT_REVOKED":
                    event_name = "SESSION_REVOKED"
                db.add(
                    SessionEvent(
                        session_id=session.id,
                        event_type=event_name,
                        timestamp=now,
                        details={"reason": reason or "Normal termination"},
                    )
                )
                await db.commit()
    except Exception as exc:
        logger.error("Failed to update closed session state in DB for %s: %s", session_id, exc)


@router.websocket("/ssh/{session_id}/ws")
async def ssh_terminal_websocket(
    websocket: WebSocket,
    session_id: uuid.UUID,
    ticket: Optional[str] = None,
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
    terminal_gateway: AsyncSSHTerminalGateway = Depends(get_terminal_gateway),
    credentials: CredentialService = Depends(get_credential_service),
):
    """
    Authenticated WebSocket terminal bridge for live interactive SSH sessions.

    Security & Integrity Controls:
    - Ticket required: Must be presented via query param ?ticket= or initial JSON auth frame.
    - Single-use atomic consumption via Redis GETDEL.
    - Bound cryptographically to session_id, user_id, asset_id, request_id, and jit_grant_id.
    - Authoritative database revalidation of user, asset, request, and live JIT grant.
    - Zero secret exposure: passwords, keys, or internal errors are never sent over WebSocket.
    - Strict cleanup (F-02): proc, SSH connection, and registry entries are unconditionally cleaned up.
    - State transitions: session transitions STARTING -> ACTIVE -> COMPLETED (or FAILED/EXPIRED).
    """
    await websocket.accept()

    # 1. Ticket extraction
    if not ticket:
        ticket = websocket.query_params.get("ticket")

    if not ticket:
        try:
            first_msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            try:
                parsed = json.loads(first_msg)
                if isinstance(parsed, dict) and parsed.get("type") == "auth":
                    ticket = parsed.get("ticket")
                elif isinstance(parsed, dict) and "ticket" in parsed:
                    ticket = parsed.get("ticket")
            except (json.JSONDecodeError, ValueError):
                pass
        except (asyncio.TimeoutError, WebSocketDisconnect):
            pass

    if not ticket or not isinstance(ticket, str):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Ticket required")
        return

    # 2. Authoritative database validation & ticket consumption
    user: Optional[User] = None
    asset: Optional[Asset] = None
    access_request: Optional[AccessRequest] = None
    grant_expires_at: Optional[datetime] = None
    live_conn = None

    async with async_session_factory() as db:
        session = await db.get(Session, session_id)
        if session is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
            return

        if session.status not in ("STARTING", "ACTIVE"):
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason=f"Session is not connectable ({session.status})",
            )
            return

        # Atomically consume ticket (Fix F-04: validates binding to session, user, and asset)
        try:
            ticket_data = await ticket_service.consume_ticket(
                ticket=ticket,
                expected_session_id=session.id,
                expected_user_id=session.user_id,
                expected_asset_id=session.asset_id,
            )
        except SSHTicketInvalidError as exc:
            logger.warning("SSH ticket invalid for session %s: %s", session.id, exc)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=str(exc))
            return
        except SSHTicketStorageError as exc:
            logger.error("SSH ticket storage unavailable for session %s: %s", session.id, exc)
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Ticket verification unavailable")
            return

        # Authoritative state checks
        user = await db.get(User, session.user_id)
        if user is None or not user.is_active or user.is_deleted:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User account is inactive or disabled")
            return

        asset = await db.get(Asset, session.asset_id)
        if asset is None or not asset.enabled or asset.status != "ACTIVE" or asset.is_deleted:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Target asset is not available")
            return

        access_request = await db.get(AccessRequest, session.request_id)
        if access_request is None or access_request.status != "ACTIVE":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access request is not active")
            return

        # Revalidate JIT grant before establishing live SSH connection
        grant = await _jit.validate(db, user_id=user.id, target_id=asset.id, protocol="SSH")
        if grant is None or grant.id != session.jit_grant_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="JIT grant is expired or invalid")
            return

        grant_expires_at = grant.expires_at
        session_user_id = session.user_id
        session_asset_id = session.asset_id
        session_request_id = session.request_id
        session_jit_grant_id = session.jit_grant_id

        # Check if live connection is already registered
        live_conn = terminal_gateway.get_live_connection(session.id)
        connection_acquired = live_conn is not None and not live_conn.is_closed
        if not connection_acquired:
            client_host = websocket.client.host if websocket.client else None
            checkout = CheckoutRequest(
                user_id=user.id,
                access_request_id=access_request.id,
                jit_grant_id=grant.id,
                asset_id=asset.id,
                session_id=session.id,
                source_ip=client_host,
            )
            try:
                async with credentials.checkout(db, checkout) as credential:
                    await terminal_gateway.prepare(session=session, asset=asset, credential=credential)
                connection_acquired = True
                live_conn = terminal_gateway.get_live_connection(session.id)
            except Exception as exc:
                logger.error("Failed to establish live SSH connection for session %s: %s", session.id, exc)
                await _close_session_in_db(session.id, status_val="FAILED", reason="SSH_HANDSHAKE_FAILED")
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="SSH connection failed")
                return

        if live_conn is None or live_conn.is_closed:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Failed to acquire active SSH transport")
            return

    # From here onward, live_conn is active and registered in gateway.
    # Unified try/finally ensures unconditional cleanup of SSH transport on any failure or cancellation.
    proc = None
    stdout_task = None
    stdin_task = None
    jit_task = None
    final_status = "COMPLETED"
    final_reason = "SESSION_TERMINATED"

    try:
        # Transition session state in DB
        now = datetime.now(timezone.utc)
        async with async_session_factory() as db:
            session = await db.get(Session, session_id)
            user = await db.get(User, session_user_id)
            asset = await db.get(Asset, session_asset_id)
            if session:
                session.status = "ACTIVE"
                if session.start_time is None:
                    session.start_time = now
                if session.recording_id:
                    rec = await db.get(Recording, session.recording_id)
                    if rec:
                        # Truthful recording status: Member 10 does not yet capture terminal streams;
                        # keep status PENDING rather than falsely asserting RECORDING.
                        rec.status = "PENDING"
                db.add(SessionEvent(session_id=session.id, event_type="SESSION_STARTED", timestamp=now, details={"protocol": "SSH"}))
                await write_audit_log(
                    db,
                    actor=user,
                    action="SESSION_STARTED",
                    target_type="asset",
                    target_id=str(asset.id),
                    request_id=session_request_id,
                    session_id=session.id,
                    source_ip=websocket.client.host if websocket.client else None,
                    result="SUCCESS",
                    severity="INFO",
                    metadata={"protocol": "SSH", "session_number": session.session_number, "recording_captured": False},
                )
                await db.commit()

        # 3. Create interactive PTY process
        conn = live_conn.connection
        proc = await conn.create_process(
            term_type="xterm-256color",
            term_size=(DEFAULT_COLS, DEFAULT_ROWS),
            encoding="utf-8",
        )

        # 4. Bidirectional terminal pump with periodic JIT & auth revalidation
        async def stdout_pump():
            try:
                while True:
                    chunk = await proc.stdout.read(MAX_TERMINAL_CHUNK_SIZE)
                    if not chunk:
                        # Target process closed (EOF)
                        try:
                            await websocket.send_text(json.dumps({"type": "closed", "reason": "Target process terminated"}))
                        except Exception:
                            pass
                        break
                    await websocket.send_text(json.dumps({"type": "output", "data": chunk}))
            except (asyncio.CancelledError, WebSocketDisconnect):
                pass
            except Exception as exc:
                logger.warning("Error in SSH stdout pump for session %s: %s", session_id, exc)

        async def stdin_pump():
            try:
                while True:
                    msg = await websocket.receive_text()
                    if len(msg) > MAX_TERMINAL_CHUNK_SIZE * 2:
                        logger.warning("Dropped oversized message (%d bytes) for session %s", len(msg), session_id)
                        continue

                    if msg.startswith("{") and msg.endswith("}"):
                        try:
                            data = json.loads(msg)
                            msg_type = data.get("type")
                            if msg_type == "input":
                                raw_input = data.get("data", "")
                                if isinstance(raw_input, str):
                                    proc.stdin.write(raw_input)
                                continue
                            elif msg_type == "resize":
                                cols = data.get("cols") or data.get("width")
                                rows = data.get("rows") or data.get("height")
                                if isinstance(cols, int) and isinstance(rows, int):
                                    valid_cols = max(MIN_COLS, min(cols, MAX_COLS))
                                    valid_rows = max(MIN_ROWS, min(rows, MAX_ROWS))
                                    try:
                                        proc.change_terminal_size(valid_cols, valid_rows)
                                    except Exception as exc:
                                        logger.warning("Terminal resize failed: %s", exc)
                                continue
                            elif msg_type == "ping":
                                await websocket.send_text(json.dumps({"type": "pong"}))
                                continue
                        except json.JSONDecodeError:
                            pass

                    # Fallback: treat as raw text input
                    proc.stdin.write(msg)
            except (asyncio.CancelledError, WebSocketDisconnect):
                pass
            except Exception as exc:
                logger.warning("Error in SSH stdin pump for session %s: %s", session_id, exc)

        async def jit_auth_monitor():
            nonlocal final_status, final_reason
            consecutive_errors = 0
            MAX_CONSECUTIVE_AUTH_ERRORS = 2

            try:
                while True:
                    now_utc = datetime.now(timezone.utc)
                    if grant_expires_at is not None:
                        remaining = (grant_expires_at - now_utc).total_seconds()
                        if remaining <= 0:
                            logger.info("JIT grant expired for session %s", session_id)
                            final_status = "EXPIRED"
                            final_reason = "JIT_GRANT_EXPIRED"
                            try:
                                await websocket.send_text(
                                    json.dumps({"type": "error", "message": "JIT grant has expired. Session terminating."})
                                )
                            except Exception:
                                pass
                            break

                    # Periodic database revalidation of JIT grant, request, user, and asset
                    try:
                        async with async_session_factory() as poll_db:
                            g = await poll_db.get(JITGrant, session_jit_grant_id)
                            ar = await poll_db.get(AccessRequest, session_request_id)
                            u = await poll_db.get(User, session_user_id)
                            a = await poll_db.get(Asset, session_asset_id)

                            if (
                                g is None
                                or g.status != "ACTIVE"
                                or g.revoked_at is not None
                                or ar is None
                                or ar.status != "ACTIVE"
                            ):
                                logger.info("JIT grant or access request revoked for session %s", session_id)
                                final_status = "EXPIRED"
                                final_reason = "JIT_GRANT_REVOKED"
                                try:
                                    await websocket.send_text(
                                        json.dumps({"type": "error", "message": "Access authorization has been revoked. Session terminating."})
                                    )
                                except Exception:
                                    pass
                                break

                            if (
                                u is None
                                or not u.is_active
                                or u.is_deleted
                                or a is None
                                or not a.enabled
                                or a.status != "ACTIVE"
                                or a.is_deleted
                            ):
                                logger.info("User or target asset disabled/deleted for session %s", session_id)
                                final_status = "FAILED"
                                final_reason = "AUTHORIZATION_REVOKED"
                                try:
                                    await websocket.send_text(
                                        json.dumps({"type": "error", "message": "User or target asset is no longer active. Session terminating."})
                                    )
                                except Exception:
                                    pass
                                break

                        consecutive_errors = 0
                    except Exception as exc:
                        consecutive_errors += 1
                        logger.warning(
                            "Error revalidating authorization for session %s (failure %d/%d): %s",
                            session_id, consecutive_errors, MAX_CONSECUTIVE_AUTH_ERRORS, exc,
                        )
                        if consecutive_errors >= MAX_CONSECUTIVE_AUTH_ERRORS:
                            logger.error("Authoritative check failed repeatedly for session %s; terminating fail-closed", session_id)
                            final_status = "FAILED"
                            final_reason = "AUTH_REVALIDATION_FAILED"
                            try:
                                await websocket.send_text(
                                    json.dumps({"type": "error", "message": "Authorization verification unavailable. Session terminating."})
                                )
                            except Exception:
                                pass
                            break

                    sleep_dur = 1.0
                    if grant_expires_at is not None:
                        rem = (grant_expires_at - datetime.now(timezone.utc)).total_seconds()
                        if rem > 0:
                            sleep_dur = min(rem, 1.0)
                        else:
                            sleep_dur = 0.05
                    await asyncio.sleep(sleep_dur)
            except asyncio.CancelledError:
                pass

        stdout_task = asyncio.create_task(stdout_pump())
        stdin_task = asyncio.create_task(stdin_pump())
        jit_task = asyncio.create_task(jit_auth_monitor())

        done, pending = await asyncio.wait(
            [stdout_task, stdin_task, jit_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
    except Exception as exc:
        final_status = "FAILED"
        final_reason = f"ERROR: {type(exc).__name__}"
        logger.error("Error in live SSH session %s: %s", session_id, exc)
    finally:
        with anyio.CancelScope(shield=True):
            # Cancel all background tasks
            for t in (stdout_task, stdin_task, jit_task):
                if t and not t.done():
                    t.cancel()

            # Close PTY process
            if proc:
                try:
                    proc.close()
                except Exception:
                    pass

            # Fix F-02: Unconditionally close connection and remove from active registry
            try:
                await terminal_gateway.close_connection(session_id)
            except Exception as exc:
                logger.warning("Error closing SSH connection in gateway for %s: %s", session_id, exc)

            # Update database session state
            try:
                await _close_session_in_db(
                    session_id,
                    status_val=final_status,
                    reason=final_reason,
                )
            except Exception as exc:
                logger.warning("Error updating session termination in DB for %s: %s", session_id, exc)

            # Close WebSocket if still open
            try:
                close_code = (
                    status.WS_1008_POLICY_VIOLATION
                    if final_status in ("EXPIRED", "FAILED")
                    else status.WS_1000_NORMAL_CLOSURE
                )
                await websocket.close(code=close_code)
            except Exception:
                pass
