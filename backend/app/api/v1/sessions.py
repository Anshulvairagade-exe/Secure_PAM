"""
Sessions API Router — M9 RDP Gateway & Session Orchestration.

Authorization:
- list/detail: sessions:read sees every session; sessions:read_own sees
  only the caller's. Someone else's session is 404 (not 403) for an
  own-scope caller, matching access_requests.py, so its existence isn't
  confirmed.
- terminate: sessions:terminate may end any session; an owner may end
  their own. Anyone else is refused.
- RDP launch: sessions:create, then the caller's own ACTIVE access request
  for that RDP asset, a live JIT grant from JITService.validate() bound to
  that request, and a CredentialService checkout bound to the new session.
  Any failure marks the session FAILED; nothing is reported as started.
  The response never contains a credential or a filesystem path.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import apply_sorting, paginate
from app.schemas.common import PaginatedResponse, PaginationParams
from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db, user_has_permission
from app.core.security import generate_session_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)
from app.services.jit_service import JITService
from app.services.credential_errors import (
    credential_denied_error, credential_unavailable_error, failure_message, gateway_error,
)
from app.services.browser_isolation import get_browser_isolation_gateway
from app.services.rdp_recording import session_recording_file
from app.services.session_policy import acquire_slot
from app.services.ssh_ticket import SSHTicketService, get_ssh_ticket_service
from app.services.session_termination import terminate_session as terminate_session_service
from app.services.ssh_terminal_gateway import AsyncSSHTerminalGateway, get_terminal_gateway
from app.services.rdp_gateway import GatewayError, RDPGateway, get_rdp_gateway, rdp_recording_writable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sessions", tags=["Sessions"])

LIVE_STATUSES = {"CREATED", "STARTING", "ACTIVE", "TERMINATING"}
_SESSION_STATUSES = {"CREATED", "STARTING", "ACTIVE", "TERMINATING", "TERMINATED", "COMPLETED", "FAILED", "EXPIRED"}
_SORTABLE_COLUMNS = {"created_at", "start_time", "end_time", "status", "protocol", "session_number"}
_jit = JITService()


def get_credential_service() -> CredentialService:
    return CredentialService()


class CreateRDPSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: uuid.UUID
    asset_id: uuid.UUID


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_number: str
    user_id: uuid.UUID
    asset_id: Optional[uuid.UUID]
    request_id: uuid.UUID
    protocol: str
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    recording_id: Optional[uuid.UUID]
    # The grant that authorized this session — the admin UI uses it to
    # revoke access (IDs only, never credentials).
    jit_grant_id: Optional[uuid.UUID] = None
    asset_name: Optional[str] = None
    recording_status: Optional[str] = None
    # FAILED sessions: the stable reason code and a safe, actionable message.
    failure_reason: Optional[str] = None
    failure_message: Optional[str] = None


def _can_view_all(user: User) -> bool:
    return user_has_permission(user, "sessions", "read")


async def _get_visible_session_or_404(db: AsyncSession, session_id: uuid.UUID, user: User) -> Session:
    session = await db.get(Session, session_id)
    if session is None or (not _can_view_all(user) and session.user_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return session



async def _enrich_session(db: AsyncSession, item: "SessionResponse") -> None:
    """Joined, display-only fields shared by the list and detail endpoints."""
    if item.asset_id:
        asset = await db.get(Asset, item.asset_id)
        item.asset_name = asset.name if asset else None
    if item.recording_id:
        recording = await db.get(Recording, item.recording_id)
        item.recording_status = recording.status if recording else None
    if item.status == "FAILED":
        event = (await db.execute(
            select(SessionEvent)
            .where(SessionEvent.session_id == item.id)
            .order_by(SessionEvent.timestamp.desc())
        )).scalars().first()
        reason = (event.details or {}).get("reason") if event else None
        if reason:
            item.failure_reason = reason
            item.failure_message = failure_message(reason)


@router.get("/", response_model=PaginatedResponse[SessionResponse])
async def list_sessions(
    pagination: PaginationParams = Depends(),
    status_filter: Optional[str] = Query(None, alias="status", max_length=20),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        PermissionChecker("sessions", "read", "read_own")
    ),
):
    """List sessions visible to the caller, with optional status filtering and pagination."""
    query = select(Session)

    # Preserve the existing ownership restriction.
    if not _can_view_all(current_user):
        query = query.where(Session.user_id == current_user.id)

    # Preserve existing status validation.
    if status_filter:
        normalized_status = status_filter.upper()
        if normalized_status not in _SESSION_STATUSES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Unknown session status",
            )
        query = query.where(Session.status == normalized_status)

    query = apply_sorting(
        query,
        Session,
        pagination.sort_by,
        pagination.sort_order,
        _SORTABLE_COLUMNS,
    )

    # Preserve newest-first ordering when sorting isn't allowlisted.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(Session.created_at.desc())

    page = await paginate(db, query, pagination, schema=SessionResponse)
    for item in page.items:
        await _enrich_session(db, item)
    return page



@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "read", "read_own")),
):
    """Retrieve details for a single session."""
    item = SessionResponse.model_validate(await _get_visible_session_or_404(db, session_id, current_user))
    await _enrich_session(db, item)
    return item


async def _fail_launch(
    db: AsyncSession, *, session: Session, recording: Optional[Recording], actor: User,
    reason: str, source_ip: Optional[str],
) -> None:
    now = datetime.now(timezone.utc)
    session.status = "FAILED"
    session.end_time = now
    if recording:
        recording.status = "FAILED"
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_FAILED", timestamp=now, details={"reason": reason}))
    await write_audit_log(
        db, actor=actor, action="SESSION_LAUNCH_FAILED", target_type="asset", target_id=str(session.asset_id),
        request_id=session.request_id, session_id=session.id, source_ip=source_ip,
        result="FAILURE", severity="HIGH", metadata={"reason": reason, "protocol": session.protocol},
    )
    await db.commit()


@router.post("/rdp/launch", status_code=status.HTTP_201_CREATED)
async def launch_rdp_session(
    payload: CreateRDPSessionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "create")),
    credentials: CredentialService = Depends(get_credential_service),
    gateway: RDPGateway = Depends(get_rdp_gateway),
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
):
    """
    Launch an RDP session via the gateway. The credential is checked out
    server-side and handed only to the gateway; the client receives the
    session identifiers and non-secret connection details.
    """
    source_ip = client_ip(request)

    asset = (await db.execute(
        select(Asset).where(Asset.id == payload.asset_id, Asset.is_deleted == False)
    )).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target asset not found")

    access_request = await db.get(AccessRequest, payload.request_id)
    if access_request is None or access_request.user_id != current_user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")
    if access_request.asset_id != asset.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Access request is for a different target")
    if asset.protocol != "RDP" or access_request.protocol != "RDP":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target and request must both be RDP")

    async def deny(reason: str, detail: str):
        await write_audit_log(
            db, actor=current_user, action="SESSION_LAUNCH_DENIED", target_type="asset", target_id=str(asset.id),
            request_id=access_request.id, source_ip=source_ip, result="DENIED", severity="MEDIUM",
            metadata={"reason": reason, "protocol": "RDP"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)

    if not asset.enabled or asset.status != "ACTIVE":
        await deny("ASSET_DISABLED", "This target is not available.")
    if access_request.status != "ACTIVE":
        await deny("ACCESS_REQUEST_NOT_ACTIVE", "This access request is not active.")

    # The grant issued for THIS request (not merely the user's newest grant).
    grant = await _jit.grant_for_request(
        db, request_id=access_request.id, user_id=current_user.id, target_id=asset.id, protocol="RDP"
    )
    if grant is None:
        await deny("NO_VALID_JIT_GRANT", "No valid just-in-time grant for this request.")

    # No gateway, no session: a row that nothing can connect or record would
    # only masquerade as access. Refuse before any session or credential read.
    deployed = getattr(gateway, "is_deployed", True)
    if deployed and hasattr(gateway, "available"):
        deployed = await gateway.available()  # a configured but unreachable guacd is not a gateway
    if not deployed:
        await write_audit_log(
            db, actor=current_user, action="SESSION_LAUNCH_DENIED", target_type="asset", target_id=str(asset.id),
            request_id=access_request.id, source_ip=source_ip, result="FAILURE", severity="MEDIUM",
            metadata={"reason": "GATEWAY_UNAVAILABLE", "protocol": "RDP"},
        )
        await db.commit()
        raise gateway_error("GATEWAY_UNAVAILABLE")

    if (asset.recording_required or access_request.recording_required) and not rdp_recording_writable():
        await deny("RECORDING_UNAVAILABLE",
                   "This target requires session recording, but RDP recording storage is unavailable.")

    await acquire_slot(db, current_user, protocol="RDP", source_ip=source_ip,
                       request_id=access_request.id, asset_id=asset.id)

    session = Session(
        session_number=generate_session_number(), user_id=current_user.id, asset_id=asset.id,
        request_id=access_request.id, jit_grant_id=grant.id, protocol="RDP", status="STARTING",
        source_ip=source_ip, risk_score=access_request.risk_score,
    )
    db.add(session)
    await db.flush()

    recording: Optional[Recording] = None
    if asset.recording_required or access_request.recording_required:
        recording = Recording(
            session_id=session.id, recording_type="VIDEO", status="PENDING",
            file_path=str(session_recording_file(session.id)),
        )
        db.add(recording)
        await db.flush()
        session.recording_id = recording.id

    db.add(SessionEvent(session_id=session.id, event_type="SESSION_CREATED",
                        timestamp=datetime.now(timezone.utc), details={"protocol": "RDP"}))
    await db.commit()

    checkout = CheckoutRequest(
        user_id=current_user.id, access_request_id=access_request.id, jit_grant_id=grant.id,
        asset_id=asset.id, session_id=session.id, source_ip=source_ip,
    )
    try:
        async with credentials.checkout(db, checkout) as credential:
            connection = await gateway.prepare(session=session, asset=asset, credential=credential)
    except CredentialAccessDenied as exc:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason=exc.reason, source_ip=source_ip)
        raise credential_denied_error(exc.reason)
    except CredentialUnavailable as exc:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason=exc.reason, source_ip=source_ip)
        logger.warning("rdp_launch_failed session=%s asset=%s reason=%s", session.id, asset.id, exc.reason)
        raise credential_unavailable_error(exc.reason)
    except GatewayError:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason="GATEWAY_ERROR", source_ip=source_ip)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Session gateway could not start the session.")

    now = datetime.now(timezone.utc)
    session.gateway_session_id = connection.gateway_session_id
    if not connection.is_connected:
        # Prepared, not connected: the browser redeems its one-time ticket on the RDP WebSocket,
        # which makes the real connection. Until then this is STARTING, never ACTIVE.
        db.add(SessionEvent(session_id=session.id, event_type="SESSION_PREPARED", timestamp=now,
                            details={"protocol": "RDP", "pending_connection": True}))
        await write_audit_log(
            db, actor=current_user, action="SESSION_PREPARED", target_type="asset", target_id=str(asset.id),
            request_id=access_request.id, session_id=session.id, source_ip=source_ip, result="SUCCESS",
            severity="INFO", metadata={"protocol": "RDP", "session_number": session.session_number,
                                       "jit_grant_id": str(grant.id), "status": "STARTING"},
        )
        await db.commit()
        try:
            ticket = await ticket_service.issue_ticket(
                session_id=session.id, user_id=current_user.id, asset_id=asset.id,
                access_request_id=access_request.id, jit_grant_id=grant.id, ttl_seconds=60,
            )
        except Exception:
            await _fail_launch(db, session=session, recording=recording, actor=current_user,
                               reason="TICKET_GENERATION_FAILED", source_ip=source_ip)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to issue session connection ticket.")
        return {
            "session_id": str(session.id),
            "session_number": session.session_number,
            "status": "STARTING",
            "recording_id": str(recording.id) if recording else None,
            "ticket": ticket,
            "ws_url": f"/api/v1/sessions/rdp/{session.id}/ws",
            "connection": {"protocol": "rdp", "target_asset": asset.name, "is_connected": False},
            "message": "Session prepared. The desktop connects when the browser redeems its one-time ticket.",
        }
    session.status = "ACTIVE"
    session.start_time = now
    if recording:
        recording.status = "RECORDING"
    event, message = "SESSION_STARTED", "RDP session connected through the SecurePAM gateway."
    db.add(SessionEvent(session_id=session.id, event_type=event, timestamp=now,
                        details={"protocol": "RDP", "recording": recording is not None}))
    await write_audit_log(
        db, actor=current_user, action=event, target_type="asset", target_id=str(asset.id),
        request_id=access_request.id, session_id=session.id, source_ip=source_ip,
        result="SUCCESS", severity="INFO",
        metadata={"protocol": "RDP", "session_number": session.session_number,
                  "jit_grant_id": str(grant.id), "recording": recording is not None},
    )
    await db.commit()

    return {
        "session_id": str(session.id),
        "session_number": session.session_number,
        "status": session.status,
        "recording_id": str(recording.id) if recording else None,
        "connection": {"protocol": connection.protocol, "hostname": connection.hostname, "port": connection.port,
                       "is_connected": connection.is_connected},
        "message": message,
    }


class TerminateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(None, max_length=300)


@router.post("/{session_id}/terminate")
async def terminate_session(
    session_id: uuid.UUID,
    request: Request,
    body: Optional[TerminateBody] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "terminate", "read", "read_own")),
    gateway: AsyncSSHTerminalGateway = Depends(get_terminal_gateway),
    rdp_gateway: RDPGateway = Depends(get_rdp_gateway),
    web_gateway=Depends(get_browser_isolation_gateway),
):
    """Terminate a live session: close the real connection, settle the recording by what
    exists, audit. An administrator ending someone else's session also revokes its JIT
    grant (no reconnecting with it); an owner ending their own keeps the grant."""
    session = await _get_visible_session_or_404(db, session_id, current_user)

    is_owner = session.user_id == current_user.id
    if not is_owner and not user_has_permission(current_user, "sessions", "terminate"):
        await write_audit_log(
            db, actor=current_user, action="ACCESS_DENIED", target_type="session", target_id=str(session.id),
            session_id=session.id, source_ip=client_ip(request), result="DENIED", severity="MEDIUM",
            metadata={"required_permission": "sessions:terminate"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not authorized to terminate this session.")

    if session.status not in LIVE_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Session is already {session.status}")

    result = await terminate_session_service(
        db, session, actor=current_user, source_ip=client_ip(request), gateway=gateway, rdp_gateway=rdp_gateway, web_gateway=web_gateway,
        reason=body.reason if body else None, revoke_grant=not is_owner,
        final_status="COMPLETED" if is_owner else "TERMINATED",
    )
    payload = {"message": "Session terminated successfully" if result.ok else "Session termination was incomplete",
               "session_id": str(session_id), "complete": result.ok, "result": result.dict()}
    if not result.ok:
        return JSONResponse(payload, status_code=status.HTTP_207_MULTI_STATUS)
    return payload
