"""
Isolated-browser sessions for registered HTTP/HTTPS applications.

    POST /sessions/web/launch      operator: approved request + live JIT grant -> isolated browser
    WS   /sessions/web/{id}/ws     one-time ticket (first frame) -> authenticated VNC relay

The destination is always the server-side application record (scheme, host, port, start path,
optional pinned key): nothing in a request, header, query or WebSocket message can change it. A
session is ACTIVE only after the daemon reports the registered page loaded AND the relay to it is up.
Expiry, revocation, deactivation and admin termination are enforced by a per-second monitor that
closes the relay and destroys the browser; destination and navigation violations are audited.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from anyio import CancelScope
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ssh_sessions import _close_session_in_db
from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.core.security import generate_session_number
from app.database.session import async_session_factory
from app.models.access_request import AccessRequest
from app.models.application import Application
from app.models.jit_grant import JITGrant
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.browser_isolation import (
    UNCONNECTED_TTL, ClientMessageFilter, IsolationError, get_browser_isolation_gateway, server_handshake,
)
from app.services.jit_service import JITService
from app.services.session_policy import acquire_slot
from app.services.ssh_ticket import SSHTicketInvalidError, SSHTicketService, SSHTicketStorageError, get_ssh_ticket_service

router = APIRouter(prefix="/sessions", tags=["Isolated browser sessions"])
logger = logging.getLogger("securepam.web")
_jit = JITService()

_FAILURE_TEXT = {
    "TLS_VALIDATION_FAILED": "The application's TLS certificate failed validation (untrusted issuer, wrong host "
                             "name, expired, or the registered key pin does not match). The isolated browser was not "
                             "started.",
    "DESTINATION_BLOCKED": "The registered destination is not allowed for isolated browsing.",
    "NOT_READY_IN_TIME": "The application did not load in the isolated browser.",
    "NAVIGATION_FAILED": "The application could not be loaded in the isolated browser.",
    "ISOLATION_UNAVAILABLE": "The isolated browser service is unavailable.",
    "LAUNCH_FAILED": "The isolated browser could not be started.",
}


class WebLaunch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: uuid.UUID
    application_id: uuid.UUID


async def _audit(db, actor, action, *, session_id=None, request_id=None, application_id=None, result="SUCCESS",
                 severity="INFO", **metadata):
    await write_audit_log(db, actor=actor, action=action, target_type="application",
                          target_id=str(application_id) if application_id else None, request_id=request_id,
                          session_id=session_id, result=result, severity=severity, metadata=metadata)


@router.post("/web/launch", status_code=status.HTTP_201_CREATED)
async def launch_web_session(
    payload: WebLaunch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "create")),
    gateway=Depends(get_browser_isolation_gateway),
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
):
    source_ip = client_ip(request)
    app_row = await db.get(Application, payload.application_id)
    if app_row is None or app_row.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    access_request = await db.get(AccessRequest, payload.request_id)
    if access_request is None or access_request.user_id != current_user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")
    if access_request.application_id != app_row.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Access request is for a different target")
    if app_row.protocol not in ("HTTP", "HTTPS") or access_request.protocol != app_row.protocol:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target and request must both be HTTP/HTTPS")

    async def deny(reason: str, detail: str, code: int = status.HTTP_403_FORBIDDEN):
        await _audit(db, current_user, "SESSION_LAUNCH_DENIED", request_id=access_request.id,
                     application_id=app_row.id, result="DENIED", severity="MEDIUM", reason=reason,
                     protocol=app_row.protocol)
        await db.commit()
        raise HTTPException(code, detail)

    if app_row.access_mode != "ISOLATED_BROWSER":
        await deny("ACCESS_MODE_NOT_ISOLATED", "This application is not configured for isolated browsing.")
    if not app_row.enabled or app_row.status != "ACTIVE":
        await deny("APPLICATION_DISABLED", "This application is not available.")
    if access_request.status != "ACTIVE":
        await deny("ACCESS_REQUEST_NOT_ACTIVE", "This access request is not active.")
    grant = await _jit.grant_for_request(db, request_id=access_request.id, user_id=current_user.id,
                                         target_id=app_row.id, protocol=app_row.protocol)
    if grant is None:
        await deny("NO_VALID_JIT_GRANT", "No valid just-in-time grant for this request.")
    if app_row.recording_required or access_request.recording_required:
        # Screen recording of isolated-browser sessions is not implemented: refuse rather than run unrecorded.
        await deny("RECORDING_UNAVAILABLE", "This application requires session recording, which isolated "
                   "browser sessions do not provide yet.")
    if not getattr(gateway, "is_deployed", False) or not await gateway.available():
        await deny("GATEWAY_UNAVAILABLE", _FAILURE_TEXT["ISOLATION_UNAVAILABLE"], status.HTTP_503_SERVICE_UNAVAILABLE)

    await acquire_slot(db, current_user, protocol=app_row.protocol, source_ip=source_ip,
                       request_id=access_request.id, asset_id=None)
    session = Session(session_number=generate_session_number(), user_id=current_user.id, application_id=app_row.id,
                      request_id=access_request.id, jit_grant_id=grant.id, protocol=app_row.protocol,
                      status="STARTING", source_ip=source_ip, risk_score=access_request.risk_score)
    db.add(session)
    await db.flush()
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_CREATED", timestamp=datetime.now(timezone.utc),
                        details={"protocol": app_row.protocol, "mode": "ISOLATED_BROWSER"}))
    await db.commit()

    async def fail(reason: str, http: int):
        await gateway.stop(session.id)
        await _close_session_in_db(session.id, status_val="FAILED", reason=reason)
        action = "TLS_VALIDATION_FAILED" if reason == "TLS_VALIDATION_FAILED" else (
            "DESTINATION_DENIED" if reason == "DESTINATION_BLOCKED" else "SESSION_LAUNCH_FAILED")
        await _audit(db, current_user, action, session_id=session.id, request_id=access_request.id,
                     application_id=app_row.id, result="FAILURE", severity="HIGH", reason=reason,
                     destination=f"{app_row.protocol.lower()}://{app_row.hostname}:{app_row.port}")
        await db.commit()
        raise HTTPException(http, _FAILURE_TEXT.get(reason, _FAILURE_TEXT["LAUNCH_FAILED"]))

    ttl = max(60, int((grant.expires_at - datetime.now(timezone.utc)).total_seconds()))
    try:
        await gateway.launch(session_id=session.id, scheme=app_row.protocol.lower(), host=app_row.hostname,
                             port=app_row.port, path=app_row.start_path or "/", tls_pin=app_row.tls_pin_sha256,
                             clipboard_allowed=app_row.clipboard_allowed, ttl_seconds=ttl)
    except IsolationError as exc:
        await fail(exc.code, status.HTTP_502_BAD_GATEWAY if exc.code != "ISOLATION_UNAVAILABLE" else 503)
    state = await gateway.wait_ready(session.id)
    if state.get("state") != "READY":
        await fail(state.get("failure") or "NOT_READY_IN_TIME", status.HTTP_502_BAD_GATEWAY)

    ticket = await ticket_service.issue_ticket(session_id=session.id, user_id=current_user.id, asset_id=app_row.id,
                                               access_request_id=access_request.id, jit_grant_id=grant.id, ttl_seconds=60)
    await _audit(db, current_user, "SESSION_PREPARED", session_id=session.id, request_id=access_request.id,
                 application_id=app_row.id, protocol=app_row.protocol, mode="ISOLATED_BROWSER",
                 session_number=session.session_number, status="STARTING")
    await db.commit()
    asyncio.get_event_loop().create_task(_reap_if_unconnected(gateway, session.id))
    return {"session_id": str(session.id), "session_number": session.session_number, "status": "STARTING",
            "recording_id": None, "ticket": ticket, "ws_url": f"/api/v1/sessions/web/{session.id}/ws",
            "connection": {"protocol": app_row.protocol.lower(), "target_application": app_row.name, "is_connected": False},
            "message": "The isolated browser has loaded the application. It connects when the browser redeems its ticket."}


async def _reap_if_unconnected(gateway, session_id) -> None:
    """A prepared browser whose operator never connects, or whose session is ended before connecting,
    must not keep running."""
    while True:
        await asyncio.sleep(2)
        live = gateway.get_live_connection(session_id)
        if live is None or live.attached:
            return
        async with async_session_factory() as db:
            row = await db.get(Session, session_id)
        ended = row is None or row.status not in ("CREATED", "STARTING")
        if live.attached:  # the operator connected while the row was being read
            return
        # time.monotonic(), the clock live.created uses: the event loop's clock (uvloop under
        # uvicorn) has a different base and made fresh sessions look expired.
        if ended or time.monotonic() - live.created > UNCONNECTED_TTL:
            result = await gateway.stop(session_id)
            if not ended:
                await _close_session_in_db(session_id, status_val="FAILED", reason="LAUNCH_NOT_CONNECTED")
                await _system_audit(session_id, "SESSION_LAUNCH_FAILED", "FAILURE", "MEDIUM",
                                    {"reason": "LAUNCH_NOT_CONNECTED", "mode": "ISOLATED_BROWSER",
                                     "browser_cleaned": bool(result.get("cleaned"))})
            if not result.get("cleaned"):
                await _system_audit(session_id, "BROWSER_CLEANUP_FAILED", "FAILURE", "HIGH", {"stage": "unconnected"})
            return


async def _system_audit(session_id, action, result, severity, metadata) -> None:
    async with async_session_factory() as db:
        row = await db.get(Session, session_id)
        actor = await db.get(User, row.user_id) if row else None
        await write_audit_log(db, actor=actor, action=action, target_type="session", target_id=str(session_id),
                              session_id=session_id, request_id=row.request_id if row else None, result=result,
                              severity=severity, metadata=metadata)
        await db.commit()


async def _authorization_problem(session_id, user_id, application_id, request_id, grant_id) -> Optional[tuple]:
    async with async_session_factory() as db:
        s = await db.get(Session, session_id)
        if s is None or s.status not in ("STARTING", "ACTIVE"):
            return "COMPLETED", "SESSION_TERMINATED"
        g = await db.get(JITGrant, grant_id) if grant_id else None
        ar = await db.get(AccessRequest, request_id)
        if g is None or g.status != "ACTIVE" or g.revoked_at is not None or ar is None or ar.status != "ACTIVE":
            return "EXPIRED", "JIT_GRANT_REVOKED"
        if g.expires_at <= datetime.now(timezone.utc):
            return "EXPIRED", "JIT_GRANT_EXPIRED"
        u = await db.get(User, user_id)
        a = await db.get(Application, application_id)
        if u is None or not u.is_active or u.is_deleted or a is None or not a.enabled or a.status != "ACTIVE" or a.is_deleted:
            return "FAILED", "AUTHORIZATION_REVOKED"
    return None


@router.websocket("/web/{session_id}/ws")
async def web_session_ws(
    websocket: WebSocket,
    session_id: uuid.UUID,
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
    gateway=Depends(get_browser_isolation_gateway),
):
    await websocket.accept()

    async def refuse(reason: str) -> None:
        try:
            await websocket.send_text(json.dumps({"type": "error", "reason": reason}))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass

    ticket = None
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), 5))
        if isinstance(first, dict) and first.get("type") == "auth":
            ticket = first.get("ticket")
    except (asyncio.TimeoutError, WebSocketDisconnect, json.JSONDecodeError, ValueError, KeyError):
        pass
    if not isinstance(ticket, str) or not ticket:
        return await refuse("TICKET_REQUIRED")

    async with async_session_factory() as db:
        session = await db.get(Session, session_id)
        if session is None or session.status != "STARTING" or session.protocol not in ("HTTP", "HTTPS"):
            return await refuse("SESSION_NOT_CONNECTABLE")
        try:
            await ticket_service.consume_ticket(ticket=ticket, expected_session_id=session.id,
                                                expected_user_id=session.user_id,
                                                expected_asset_id=session.application_id)
        except (SSHTicketInvalidError, SSHTicketStorageError):
            return await refuse("TICKET_INVALID")
        ids = dict(user_id=session.user_id, application_id=session.application_id, request_id=session.request_id,
                   grant_id=session.jit_grant_id)
        session_number = session.session_number
    if await _authorization_problem(session_id, **ids):
        return await refuse("NOT_AUTHORIZED")
    live = gateway.get_live_connection(session_id) if getattr(gateway, "is_deployed", False) else None
    if live is None or live.attached:
        return await refuse("SESSION_NOT_CONNECTABLE")
    live.attached = True

    final_status, final_reason, activated, tasks = "COMPLETED", "SESSION_TERMINATED", False, []
    vnc_writer = None
    try:
        from app.core.config import settings
        vnc_reader, vnc_writer = await asyncio.wait_for(
            asyncio.open_connection(settings.BROWSER_ISOLATION_VNC_HOST, live.vnc_port), 10)
        await server_handshake(vnc_reader, vnc_writer, live.vnc_password)

        # The browser's noVNC client gets an already-authenticated stream: security type None.
        await websocket.send_text(json.dumps({"type": "ready"}))
        go = json.loads(await asyncio.wait_for(websocket.receive_text(), 10))
        if go.get("type") != "go":
            raise IsolationError("CLIENT_PROTOCOL_ERROR")
        await websocket.send_bytes(b"RFB 003.008\n")
        client_version = await asyncio.wait_for(websocket.receive_bytes(), 10)
        if not client_version.startswith(b"RFB 003.00"):
            raise IsolationError("CLIENT_PROTOCOL_ERROR")
        await websocket.send_bytes(b"\x01\x01")
        choice = await asyncio.wait_for(websocket.receive_bytes(), 10)
        if choice[:1] != b"\x01":
            raise IsolationError("CLIENT_PROTOCOL_ERROR")
        await websocket.send_bytes(b"\x00\x00\x00\x00")

        now = datetime.now(timezone.utc)
        async with async_session_factory() as db:
            row = await db.get(Session, session_id)
            if row is None or row.status != "STARTING":
                return
            row.status, row.start_time = "ACTIVE", now
            db.add(SessionEvent(session_id=session_id, event_type="SESSION_STARTED", timestamp=now,
                                details={"protocol": row.protocol, "mode": "ISOLATED_BROWSER"}))
            await write_audit_log(db, actor=await db.get(User, ids["user_id"]), action="SESSION_STARTED",
                                  target_type="application", target_id=str(ids["application_id"]),
                                  request_id=ids["request_id"], session_id=session_id,
                                  source_ip=websocket.client.host if websocket.client else None,
                                  result="SUCCESS", severity="INFO",
                                  metadata={"protocol": row.protocol, "mode": "ISOLATED_BROWSER",
                                            "session_number": session_number})
            await db.commit()
        activated = True
        flt = ClientMessageFilter(live.clipboard_allowed)

        async def to_browser():
            nonlocal final_reason
            try:
                while data := await vnc_reader.read(65536):
                    await websocket.send_bytes(data)
                final_reason = "BROWSER_PROCESS_ENDED"
            except (WebSocketDisconnect, ConnectionError, asyncio.CancelledError):
                return

        async def to_vnc():
            nonlocal final_reason, final_status
            try:
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        final_reason = "BROWSER_DISCONNECTED"; return
                    data = msg.get("bytes")
                    if data:
                        vnc_writer.write(flt.feed(data))
                        await vnc_writer.drain()
            except IsolationError as exc:
                final_status, final_reason = "FAILED", exc.code
            except (WebSocketDisconnect, ConnectionError, asyncio.CancelledError):
                return

        async def monitor():
            nonlocal final_status, final_reason
            while True:
                await asyncio.sleep(1)
                problem = await _authorization_problem(session_id, **ids)
                if problem:
                    final_status, final_reason = problem
                    return
                state = await gateway.status(session_id)
                for v in state.get("violations", [])[live.violations_seen:]:
                    # e.g. a redirect or link to an unregistered origin, or a blocked background request
                    await _system_audit(session_id, "DESTINATION_DENIED", "DENIED", "MEDIUM",
                                        {"host": v.get("host"), "port": v.get("port"), "reason": v.get("reason")})
                live.violations_seen = len(state.get("violations", [])) if state.get("violations") else live.violations_seen
                if state.get("state") in ("FAILED", "ENDED"):
                    final_status, final_reason = "FAILED", state.get("failure") or "BROWSER_PROCESS_ENDED"
                    if final_reason == "TLS_VALIDATION_FAILED":
                        await _system_audit(session_id, "TLS_VALIDATION_FAILED", "FAILURE", "HIGH", {"stage": "in_session"})
                    return

        tasks = [asyncio.create_task(to_browser()), asyncio.create_task(to_vnc()), asyncio.create_task(monitor())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (IsolationError, asyncio.TimeoutError, OSError, WebSocketDisconnect, json.JSONDecodeError) as exc:
        final_status = "FAILED"
        final_reason = exc.code if isinstance(exc, IsolationError) else "VNC_RELAY_FAILED"
        logger.warning("web relay failed session=%s reason=%s", session_id, final_reason)
    finally:
        with CancelScope(shield=True):
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if vnc_writer is not None:
                vnc_writer.close()
            cleanup = await gateway.stop(session_id)  # kills Chromium/Xvfb/x11vnc/proxy, deletes the profile
            if not cleanup.get("cleaned"):
                await _system_audit(session_id, "BROWSER_CLEANUP_FAILED", "FAILURE", "HIGH",
                                    {"leftover_count": len(cleanup.get("leftover", []))})
            await _close_session_in_db(session_id, status_val=final_status, reason=final_reason)
            async with async_session_factory() as db:
                row = await db.get(Session, session_id)
                if row is not None and row.status not in ("TERMINATING", "TERMINATED"):
                    action = "SESSION_ENDED" if activated else "SESSION_LAUNCH_FAILED"
                    await write_audit_log(db, actor=await db.get(User, ids["user_id"]), action=action,
                                          target_type="session", target_id=str(session_id), session_id=session_id,
                                          request_id=ids["request_id"],
                                          result="SUCCESS" if row.status == "COMPLETED" else "FAILURE",
                                          severity="INFO" if row.status == "COMPLETED" else "MEDIUM",
                                          metadata={"reason": final_reason, "status": row.status,
                                                    "mode": "ISOLATED_BROWSER", "browser_cleaned": bool(cleanup.get("cleaned"))})
                    await db.commit()
            try:
                await websocket.close()
            except Exception:
                pass
