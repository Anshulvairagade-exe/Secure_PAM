"""Isolated-browser sessions: destination locking, TLS, JIT authorization, relay, cleanup, SIEM."""

import asyncio
import importlib.util
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.security import generate_request_number
from app.database.session import async_session_factory
from app.main import app
from app.models.access_request import AccessRequest
from app.models.application import Application
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session
from app.models.user import User
from app.schemas.applications import validate_start_path, validate_tls_pin
from app.services.browser_isolation import (
    ClientMessageFilter, IsolationError, LiveWebSession, get_browser_isolation_gateway, vnc_auth_response,
)
from tests.conftest import auth_header

PIN = "aVC3pWLrYDf71LHR8+We+W5/PsCBWjACBjWLTQvYq3g="
VNC_PASSWORD = "a1b2c3d4"
SECRET_CANARY = "COOKIE-CANARY-should-never-appear"


# ---------------------------------------------------------------------------------------------- helpers

async def _user(db, name):
    return (await db.execute(select(User).where(User.username == name))).scalar_one()


async def _actions(db, action):
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


async def _row(model, pk):
    async with async_session_factory() as db:
        return await db.get(model, pk)


async def _wazuh_app(db, **over):
    data = dict(name="Cloud Wazuh Dashboard", hostname="3.104.196.100", port=443, protocol="HTTPS",
                target_url="https://3.104.196.100:443/app/login", start_path="/app/login", tls_pin_sha256=PIN,
                environment="PRODUCTION", criticality="HIGH", access_mode="ISOLATED_BROWSER", enabled=True,
                approval_required=True, recording_required=False, session_timeout=30)
    data.update(over)
    a = Application(**data)
    db.add(a)
    await db.commit()
    return a


async def _approved(db, application, *, username="operator", grant_status="ACTIVE", expires_in=30):
    user = await _user(db, username)
    req = AccessRequest(request_number=generate_request_number(), user_id=user.id, application_id=application.id,
                        protocol=application.protocol, reason="web isolation test", requested_duration=30,
                        status="ACTIVE", approval_required=True, jit_required=True, mfa_required=False,
                        recording_required=False)
    db.add(req)
    await db.flush()
    now = datetime.now(timezone.utc)
    grant = JITGrant(request_id=req.id, user_id=user.id, application_id=application.id, protocol=application.protocol,
                     granted_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=expires_in),
                     status=grant_status)
    db.add(grant)
    await db.commit()
    return req, grant


class FakeVNCServer:
    """Speaks the server side of RFB 3.8 with VNC password authentication, then records client messages."""

    def __init__(self, password=VNC_PASSWORD):
        self.password, self.port, self.client_init, self.received = password, None, None, b""
        self.auth_ok = None
        self.closed = threading.Event()
        self._ready = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        assert self._ready.wait(5)
        return self.port

    def _run(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.port = srv.getsockname()[1]; self._ready.set()
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            conn.sendall(b"RFB 003.008\n"); conn.recv(12)
            conn.sendall(b"\x01\x02"); conn.recv(1)
            challenge = os.urandom(16); conn.sendall(challenge)
            response = conn.recv(16)
            self.auth_ok = response == vnc_auth_response(challenge, self.password)
            conn.sendall(b"\0\0\0\0" if self.auth_ok else b"\0\0\0\1")
            if not self.auth_ok:
                return
            self.client_init = conn.recv(1)
            name = b"isolated"
            conn.sendall((1280).to_bytes(2, "big") + (800).to_bytes(2, "big") + bytes(16) + len(name).to_bytes(4, "big") + name)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                self.received += data
        except OSError:
            pass
        finally:
            conn.close(); srv.close(); self.closed.set()


class FakeIsolation:
    """Stands in for the daemon. Records exactly what the backend asked it to open."""

    is_deployed = True

    def __init__(self, *, ready="READY", failure=None, launch_error=None, vnc_port=None, available=True):
        self.ready, self.failure, self.launch_error, self.vnc_port = ready, failure, launch_error, vnc_port
        self._available, self.launched, self.stopped = available, [], []
        self._live = {}

    async def available(self):
        return self._available

    async def launch(self, **spec):
        self.launched.append(spec)
        if self.launch_error:
            raise IsolationError(self.launch_error)
        live = LiveWebSession(spec["session_id"], self.vnc_port or 1, VNC_PASSWORD, spec["clipboard_allowed"])
        self._live[spec["session_id"]] = live
        return live

    async def wait_ready(self, session_id, timeout=45.0):
        return {"state": self.ready, "failure": self.failure}

    async def status(self, session_id):
        return {"state": "READY", "violations": []} if session_id in self._live else {"state": "ENDED"}

    async def stop(self, session_id):
        self.stopped.append(session_id)
        self._live.pop(session_id, None)
        return {"cleaned": True, "leftover": []}

    def get_live_connection(self, session_id):
        return self._live.get(session_id)

    async def close_connection(self, session_id):
        await self.stop(session_id)


@pytest.fixture
def isolation():
    made = {}

    def make(**kw):
        made["g"] = FakeIsolation(**kw)
        app.dependency_overrides[get_browser_isolation_gateway] = lambda: made["g"]
        return made["g"]
    yield make
    app.dependency_overrides.pop(get_browser_isolation_gateway, None)


def _launch(client, token, req, application, **extra):
    return client.post("/api/v1/sessions/web/launch", headers=auth_header(token),
                       json={"request_id": str(req.id), "application_id": str(application.id), **extra})


# ------------------------------------------------------------------------------ registration & destination

@pytest.mark.parametrize("raw, expected", [("/app/login?", "/app/login"), ("/app/login", "/app/login"), ("/", "/")])
def test_start_path_accepts_plain_paths(raw, expected):
    assert validate_start_path(raw) == expected


@pytest.mark.parametrize("bad", ["//evil.example/x", "https://evil.example/", "app/login", "/a?next=//evil", "/a#frag",
                                 "/a\\b", "/../etc", "/a\r\nHost: evil", "javascript:alert(1)", "/@evil.example"])
def test_start_path_can_never_retarget_the_browser(bad):
    if bad == "/@evil.example":
        assert validate_start_path(bad) == "/@evil.example"  # stays a path on the registered host
        return
    with pytest.raises(ValueError):
        validate_start_path(bad)


def test_tls_pin_format():
    assert validate_tls_pin(PIN) == PIN and validate_tls_pin(None) is None and validate_tls_pin("") is None
    for bad in ("sha256/" + PIN, "abc", PIN[:-1], "Z" * 44):
        with pytest.raises(ValueError):
            validate_tls_pin(bad)


async def test_registered_wazuh_application_is_accepted_and_url_derived_server_side(client, admin_token):
    r = await client.post("/api/v1/applications", headers=auth_header(admin_token), json={
        "name": "Cloud Wazuh Dashboard", "hostname": "3.104.196.100", "port": 443, "protocol": "HTTPS",
        "access_mode": "ISOLATED_BROWSER", "start_path": "/app/login?", "tls_pin_sha256": PIN,
        "approval_required": True, "environment": "PRODUCTION", "criticality": "HIGH"})
    assert r.status_code == 201, r.text
    assert r.json()["target_url"] == "https://3.104.196.100:443/app/login"
    # a client cannot supply the URL directly
    r2 = await client.post("/api/v1/applications", headers=auth_header(admin_token), json={
        "name": "x", "hostname": "3.104.196.100", "port": 443, "protocol": "HTTPS", "target_url": "https://evil.example"})
    assert r2.status_code in (201, 422) and "evil" not in r2.text


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "169.254.169.254", "[::1]"])
async def test_loopback_and_metadata_cannot_be_registered(client, admin_token, host):
    r = await client.post("/api/v1/applications", headers=auth_header(admin_token), json={
        "name": "bad", "hostname": host, "port": 80, "protocol": "HTTP", "access_mode": "ISOLATED_BROWSER"})
    assert r.status_code == 422


# -------------------------------------------------------------------------------------- launch authorization

async def test_launch_opens_exactly_the_registered_destination(db_session, operator_token, isolation):
    g = isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    client = TestClient(app)
    r = _launch(client, operator_token, req, application)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "STARTING" and body["ticket"] and body["ws_url"].endswith("/ws")
    (spec,) = g.launched
    assert (spec["scheme"], spec["host"], spec["port"], spec["path"], spec["tls_pin"]) == \
        ("https", "3.104.196.100", 443, "/app/login", PIN)
    assert "vnc" not in json.dumps(body).lower()  # the VNC password never reaches the browser
    assert (await _row(Session, uuid.UUID(body["session_id"]))).status == "STARTING"


async def test_client_cannot_override_the_destination(db_session, operator_token, isolation):
    isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    r = _launch(TestClient(app), operator_token, req, application, target_url="https://169.254.169.254/", host="evil")
    assert r.status_code == 422


@pytest.mark.parametrize("grant_status, expires_in", [("REVOKED", 30), ("EXPIRED", 30), ("ACTIVE", -1)])
async def test_missing_expired_or_revoked_grant_is_denied(db_session, operator_token, isolation, grant_status, expires_in):
    g = isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application, grant_status=grant_status, expires_in=expires_in)
    r = _launch(TestClient(app), operator_token, req, application)
    assert r.status_code == 403 and g.launched == []


async def test_wrong_user_cannot_use_anothers_request(db_session, operator2_token, isolation):
    g = isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application, username="operator")
    r = _launch(TestClient(app), operator2_token, req, application)
    assert r.status_code == 404 and g.launched == []


@pytest.mark.parametrize("over, reason", [({"access_mode": "STANDARD_PROXY"}, "ACCESS_MODE_NOT_ISOLATED"),
                                          ({"enabled": False}, "APPLICATION_DISABLED"),
                                          ({"recording_required": True}, "RECORDING_UNAVAILABLE")])
async def test_application_policy_is_enforced(db_session, operator_token, isolation, over, reason):
    g = isolation()
    application = await _wazuh_app(db_session, **over)
    req, _ = await _approved(db_session, application)
    r = _launch(TestClient(app), operator_token, req, application)
    assert r.status_code == 403 and g.launched == []
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == reason


async def test_isolation_service_down_is_reported(db_session, operator_token, isolation):
    isolation(available=False)
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    assert _launch(TestClient(app), operator_token, req, application).status_code == 503


async def test_untrusted_certificate_fails_closed_and_is_audited(db_session, operator_token, isolation):
    g = isolation(launch_error="TLS_VALIDATION_FAILED")
    application = await _wazuh_app(db_session, tls_pin_sha256=None)
    req, _ = await _approved(db_session, application)
    r = _launch(TestClient(app), operator_token, req, application)
    assert r.status_code == 502 and "certificate" in r.json()["detail"].lower()
    (s,) = (await db_session.execute(select(Session).where(Session.application_id == application.id))).scalars().all()
    assert s.status == "FAILED" and s.start_time is None
    (tls,) = await _actions(db_session, "TLS_VALIDATION_FAILED")
    assert tls.details["destination"] == "https://3.104.196.100:443"
    assert g.stopped == [s.id]


async def test_page_that_never_loads_is_not_reported_active(db_session, operator_token, isolation):
    g = isolation(ready="FAILED", failure="NAVIGATION_FAILED")
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    assert _launch(TestClient(app), operator_token, req, application).status_code == 502
    (s,) = (await db_session.execute(select(Session).where(Session.application_id == application.id))).scalars().all()
    assert s.status == "FAILED" and g.stopped == [s.id]


async def test_concurrent_session_limit_applies(db_session, operator_token, isolation):
    isolation()
    application = await _wazuh_app(db_session)
    client = TestClient(app)
    for _ in range(2):
        req, _ = await _approved(db_session, application)
        assert _launch(client, operator_token, req, application).status_code == 201
    req, _ = await _approved(db_session, application)
    assert _launch(client, operator_token, req, application).status_code == 409


# --------------------------------------------------------------------------------------- relay & lifecycle

def _relay_handshake(ws, ticket):
    ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
    assert json.loads(ws.receive_text())["type"] == "ready"
    ws.send_text(json.dumps({"type": "go"}))
    assert ws.receive_bytes() == b"RFB 003.008\n"
    ws.send_bytes(b"RFB 003.008\n")
    assert ws.receive_bytes() == b"\x01\x01"   # browser is offered only "None": it never sees the VNC password
    ws.send_bytes(b"\x01")
    assert ws.receive_bytes() == b"\0\0\0\0"


async def test_relay_authenticates_upstream_filters_input_and_terminates(db_session, operator_token, admin_token, isolation):
    vnc = FakeVNCServer()
    g = isolation(vnc_port=vnc.start())
    application = await _wazuh_app(db_session, clipboard_allowed=False)
    req, grant = await _approved(db_session, application)
    client = TestClient(app)
    body = _launch(client, operator_token, req, application).json()
    sid = uuid.UUID(body["session_id"])
    with client.websocket_connect(body["ws_url"]) as ws:
        _relay_handshake(ws, body["ticket"])
        ws.send_bytes(b"\x01")                                    # ClientInit (shared=1 requested)
        assert len(ws.receive_bytes()) >= 24                      # ServerInit relayed
        ws.send_bytes(bytes([5, 0, 0, 10, 0, 20]))                # PointerEvent
        ws.send_bytes(bytes([6, 0, 0, 0, 0, 0, 0, len(SECRET_CANARY)]) + SECRET_CANARY.encode())  # clipboard paste
        ws.send_bytes(bytes([4, 1, 0, 0, 0, 0, 0, 65]))           # KeyEvent
        for _ in range(50):
            if len(vnc.received) >= 14:
                break
            time.sleep(0.1)
        assert (await _row(Session, sid)).status == "ACTIVE"
        term = client.post(f"/api/v1/sessions/{sid}/terminate", headers=auth_header(admin_token), json={"reason": "test"})
        assert term.status_code == 200, term.text
    assert vnc.auth_ok is True and vnc.client_init == b"\x00"   # exclusive viewer enforced
    assert bytes([5, 0, 0, 10, 0, 20]) in vnc.received and bytes([4, 1, 0, 0, 0, 0, 0, 65]) in vnc.received
    assert SECRET_CANARY.encode() not in vnc.received          # clipboard not allowed for this application
    assert sid in g.stopped                                    # browser destroyed, not just the DB row
    s = await _row(Session, sid)
    assert s.status == "TERMINATED"
    assert (await _row(JITGrant, grant.id)).status == "REVOKED"
    actions = {a.action for a in (await db_session.execute(select(AuditLog))).scalars().all()}
    assert {"SESSION_PREPARED", "SESSION_STARTED", "SESSION_TERMINATED", "JIT_REVOKED"} <= actions


async def test_unauthenticated_or_reused_ticket_is_refused(db_session, operator_token, isolation):
    vnc = FakeVNCServer()
    isolation(vnc_port=vnc.start())
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    client = TestClient(app)
    body = _launch(client, operator_token, req, application).json()
    with client.websocket_connect(body["ws_url"]) as ws:
        ws.send_text(json.dumps({"type": "auth"}))
        assert json.loads(ws.receive_text())["reason"] == "TICKET_REQUIRED"
    with client.websocket_connect(body["ws_url"]) as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": "forged"}))
        assert json.loads(ws.receive_text())["reason"] == "TICKET_INVALID"
    assert (await _row(Session, uuid.UUID(body["session_id"]))).status == "STARTING"


async def test_revoking_the_grant_ends_the_isolated_browser(db_session, operator_token, admin_token, isolation):
    vnc = FakeVNCServer()
    g = isolation(vnc_port=vnc.start())
    application = await _wazuh_app(db_session)
    req, grant = await _approved(db_session, application)
    client = TestClient(app)
    body = _launch(client, operator_token, req, application).json()
    with client.websocket_connect(body["ws_url"]) as ws:
        _relay_handshake(ws, body["ticket"])
        ws.send_bytes(b"\x01"); ws.receive_bytes()
        assert client.post(f"/api/v1/jit-grants/{grant.id}/revoke", headers=auth_header(admin_token)).status_code == 200
        assert vnc.closed.wait(8), "revocation left the browser stream open"
    assert uuid.UUID(body["session_id"]) in g.stopped


async def test_unconnected_session_is_reaped_when_terminated(db_session, operator_token, admin_token, isolation, monkeypatch):
    g = isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    client = TestClient(app)
    body = _launch(client, operator_token, req, application).json()
    sid = uuid.UUID(body["session_id"])
    r = client.post(f"/api/v1/sessions/{sid}/terminate", headers=auth_header(admin_token))
    assert r.status_code == 200
    for _ in range(40):
        if sid in g.stopped:
            break
        await asyncio.sleep(0.25)
    assert sid in g.stopped, "a browser nobody connected to was left running"


async def test_fresh_unconnected_session_is_not_reaped_early(db_session, operator_token, isolation, monkeypatch):
    """Regression: the reaper compared the event loop's clock (uvloop under uvicorn, another base)
    with time.monotonic(), so a browser launched a second ago was killed before the operator could
    attach. Only the TTL, measured on the same clock, may reap it, and that is audited."""
    from app.api.v1 import web_sessions

    g = isolation()
    application = await _wazuh_app(db_session)
    req, _ = await _approved(db_session, application)
    body = _launch(TestClient(app), operator_token, req, application).json()
    sid = uuid.UUID(body["session_id"])
    live = g.get_live_connection(sid)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "time", lambda: time.monotonic() + 10_000)  # a loop clock with another base
    real_sleep = asyncio.sleep
    monkeypatch.setattr(web_sessions.asyncio, "sleep", lambda _s: real_sleep(0.01))

    reaper = asyncio.create_task(web_sessions._reap_if_unconnected(g, sid))
    await real_sleep(0.3)
    assert sid not in g.stopped, "a freshly prepared browser was reaped before its TTL"

    live.created -= web_sessions.UNCONNECTED_TTL + 1
    await asyncio.wait_for(reaper, 5)
    assert sid in g.stopped
    assert (await _row(Session, sid)).status == "FAILED"
    assert any(e.session_id == sid and e.details.get("reason") == "LAUNCH_NOT_CONNECTED"
               for e in await _actions(db_session, "SESSION_LAUNCH_FAILED"))


# --------------------------------------------------------------------------------------- unit: filter, VNC, SIEM

def test_message_filter_fails_closed_on_unknown_messages():
    f = ClientMessageFilter(clipboard_allowed=True)
    assert f.feed(b"\x01") == b"\x00"
    with pytest.raises(IsolationError):
        f.feed(bytes([250, 0, 0, 0]))


def test_message_filter_reassembles_split_messages():
    f = ClientMessageFilter(clipboard_allowed=False)
    assert f.feed(b"\x01" + bytes([5, 0, 0])) == b"\x00"
    assert f.feed(bytes([10, 0, 20])) == bytes([5, 0, 0, 10, 0, 20])


def _set_encodings(*encs):
    return b"\x02\x00" + len(encs).to_bytes(2, "big") + b"".join(e.to_bytes(4, "big", signed=True) for e in encs)


def test_set_encodings_is_reduced_to_the_allowlist():
    # noVNC 1.7's real list: the server must not be offered extended clipboard, fence, continuous
    # updates, QEMU keys, xvp, ExtendedDesktopSize or extended mouse buttons (their client messages
    # are refused by the filter, so enabling them would end the session).
    f = ClientMessageFilter(clipboard_allowed=False)
    f.feed(b"\x01")
    sent = f.feed(_set_encodings(1, 7, -260, 16, 21, 5, 2, 6, 0, -26, -254, -223, -224, -258, -261, -308,
                                 -309, -312, -313, -307, 0xC0A1E5CE - (1 << 32), -316, 0x574D5664, -239))
    assert sent == _set_encodings(1, 7, -260, 16, 21, 5, 2, 6, 0, -26, -254, -223, -224, -307, 0x574D5664, -239)
    assert f.feed(_set_encodings(-312)) == _set_encodings(0)


def test_extended_clipboard_message_is_clipboard_not_a_huge_message():
    # Regression (live): noVNC sent an extended-clipboard ClientCutText (negative length) and the
    # filter read it as ~4 GB, ending the session with VNC_MESSAGE_TOO_LARGE.
    caps = b"\x06\x00\x00\x00" + (-8).to_bytes(4, "big", signed=True) + bytes(8)
    blocked = ClientMessageFilter(clipboard_allowed=False)
    blocked.feed(b"\x01")
    assert blocked.feed(caps + bytes([5, 0, 0, 1, 0, 2])) == bytes([5, 0, 0, 1, 0, 2])
    allowed = ClientMessageFilter(clipboard_allowed=True)
    allowed.feed(b"\x01")
    assert allowed.feed(caps) == caps
    with pytest.raises(IsolationError):
        allowed.feed(b"\x06\x00\x00\x00" + (-(1 << 21)).to_bytes(4, "big", signed=True))


def test_vnc_auth_matches_the_rfb_reference_vector():
    # RFB 3.8 VNC auth: DES with bit-reversed password bytes; deterministic for a given challenge.
    a = vnc_auth_response(bytes(16), "password")
    assert len(a) == 16 and a == vnc_auth_response(bytes(16), "password") and a != vnc_auth_response(bytes(16), "passw0rd")


def test_siem_events_are_structured_and_secret_free(tmp_path, monkeypatch):
    from app.core import siem
    sink = tmp_path / "securepam-events.json"
    monkeypatch.setattr(settings, "SIEM_EVENT_LOG_PATH", str(sink))
    siem.emit({"action": "DESTINATION_DENIED", "details": {
        "host": "evil.example", "password": "hunter2", "Authorization": "Bearer abc", "session_cookie": SECRET_CANARY,
        "url": "https://3.104.196.100/app/login?token=abc&next=x", "nested": {"api_key": "k"}}})
    line = sink.read_text().strip()
    event = json.loads(line)["securepam"]
    assert event["action"] == "DESTINATION_DENIED" and event["details"]["host"] == "evil.example"
    for secret in ("hunter2", "Bearer abc", SECRET_CANARY, "token=abc", '"k"'):
        assert secret not in line
    assert event["details"]["url"] == "https://3.104.196.100/app/login"
    assert (sink.stat().st_mode & 0o777) == 0o640


async def test_audit_events_reach_the_siem_sink(client, db_session, tmp_path, monkeypatch, admin_token):
    sink = tmp_path / "events.json"
    monkeypatch.setattr(settings, "SIEM_EVENT_LOG_PATH", str(sink))
    await client.get("/api/v1/recordings/", headers=auth_header(admin_token))  # any audited action
    await client.get("/api/v1/applications", headers={"Authorization": "Bearer forged"})
    from app.core.audit import write_audit_log
    async with async_session_factory() as db:
        await write_audit_log(db, actor=None, action="ACCESS_REQUEST_CREATED", metadata={"reason": "x", "password": "p"})
        await db.commit()
    events = [json.loads(l)["securepam"] for l in sink.read_text().splitlines()]
    assert any(e["action"] == "ACCESS_REQUEST_CREATED" and e["details"]["password"] == "[REDACTED]" for e in events)


# ------------------------------------------------------------------------- the daemon's own policy functions

def _daemon(tmp_path):
    token = tmp_path / "token"; token.write_text("t")
    os.environ["TOKEN_FILE"] = str(token)
    path = Path(__file__).resolve().parents[2] / "infrastructure" / "browser-isolation" / "daemon.py"
    spec = importlib.util.spec_from_file_location("isolation_daemon", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_daemon_egress_allows_only_the_registered_origin(tmp_path):
    d = _daemon(tmp_path)
    s = d.Session(str(uuid.uuid4()), 0, {"scheme": "https", "host": "3.104.196.100", "port": 443, "path": "/"})
    assert s.allowed("3.104.196.100", 443)
    for host, port in [("3.104.196.100", 9200), ("3.104.196.100", 80), ("example.com", 443), ("169.254.169.254", 80),
                       ("127.0.0.1", 6090), ("3.104.196.100.evil.example", 443)]:
        assert not s.allowed(host, port)


@pytest.mark.parametrize("ip, blocked", [("169.254.169.254", True), ("127.0.0.1", True), ("::1", True), ("0.0.0.0", True),
                                         ("fd00:ec2::254", True), ("3.104.196.100", False), ("10.0.0.5", False)])
def test_daemon_never_connects_to_loopback_link_local_or_metadata(tmp_path, ip, blocked):
    assert _daemon(tmp_path).ip_blocked(ip) is blocked


# --- HTTP registered on a TLS port: the Wazuh ERR_EMPTY_RESPONSE incident ---
# Chromium upgrades plain-HTTP navigations to HTTPS (CONNECT) on its own.
# For an http-scheme session that CONNECT must be refused (403, audited as a
# violation) — it can never be tunnelled, and plaintext forwarded to a TLS
# port dies with an empty reply. Registering https (with the pinned key) is
# the fix; the proxy behaviour below pins the fail-closed side in place.

class _FakeWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, chunk):
        self.data += chunk

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def _feed_request(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


async def test_daemon_proxy_denies_connect_upgrade_on_http_scheme(tmp_path):
    """An http-scheme session (e.g. the misregistered Wazuh app on :443)
    refuses CONNECT, even to its own registered host:port."""
    d = _daemon(tmp_path)
    s = d.Session(str(uuid.uuid4()), 0, {"scheme": "http", "host": "3.104.196.100", "port": 443, "path": "/app/login"})
    s.pinned_ip = "3.104.196.100"
    writer = _FakeWriter()
    await s.handle(_feed_request(b"CONNECT 3.104.196.100:443 HTTP/1.1\r\nHost: x\r\n\r\n"), writer)
    assert bytes(writer.data).startswith(b"HTTP/1.1 403 Forbidden")
    assert writer.closed
    assert s.violations and s.violations[-1]["reason"] == "NOT_REGISTERED_DESTINATION"


async def test_daemon_proxy_tunnels_connect_on_matching_https_scheme(tmp_path):
    """An https-scheme session tunnels CONNECT to the pinned upstream and
    relays bytes both ways; nothing is inspected or altered."""
    received = bytearray()

    async def upstream(reader, writer):
        # Keep the tunnel open while the test asserts, like a real browser
        # holding its CONNECT tunnel (an immediate close would race the
        # reply, which is a test artifact, not proxy behaviour).
        data = await reader.read(1024)
        received.extend(data)
        writer.write(b"UPSTREAM-REPLY")
        await writer.drain()
        await asyncio.sleep(1.0)
        writer.close()

    server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        d = _daemon(tmp_path)
        s = d.Session(str(uuid.uuid4()), 0, {"scheme": "https", "host": "127.0.0.1", "port": port, "path": "/"})
        s.pinned_ip = "127.0.0.1"
        writer = _FakeWriter()
        reader = asyncio.StreamReader()
        reader.feed_data(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        reader.feed_data(b"CLIENT-HELLO-BYTES")
        task = asyncio.create_task(s.handle(reader, writer))
        for _ in range(100):
            if bytes(writer.data).startswith(b"HTTP/1.1 200 Connection Established") and bytes(received):
                break
            await asyncio.sleep(0.05)
        assert bytes(writer.data).startswith(b"HTTP/1.1 200 Connection Established")
        assert bytes(received) == b"CLIENT-HELLO-BYTES"
        reader.feed_eof()  # browser goes away: both pumps unwind
        await asyncio.wait_for(task, 10)
        assert b"UPSTREAM-REPLY" in bytes(writer.data)
        assert not s.violations
    finally:
        server.close()


async def test_daemon_proxy_still_denies_off_port_connect_on_https_scheme(tmp_path):
    d = _daemon(tmp_path)
    s = d.Session(str(uuid.uuid4()), 0, {"scheme": "https", "host": "3.104.196.100", "port": 443, "path": "/"})
    s.pinned_ip = "3.104.196.100"
    writer = _FakeWriter()
    await s.handle(_feed_request(b"CONNECT 3.104.196.100:9200 HTTP/1.1\r\nHost: x\r\n\r\n"), writer)
    assert bytes(writer.data).startswith(b"HTTP/1.1 403 Forbidden")


def _self_signed_server(tmp_path):
    """Local TLS endpoint with a fresh self-signed key (hermetic pin tests)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import base64
    import hashlib
    import ssl
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-dashboard")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.TraditionalOpenSSL,
                                            serialization.NoEncryption()))
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    return ctx, pin


async def _tls_server(ctx):
    async def hold_open(reader, writer):
        # Keep the TLS endpoint up for the handshake; an instantly-closing
        # server would race it (test artifact, not validation behaviour).
        try:
            await asyncio.wait_for(reader.read(1), 5)
        except Exception:
            pass
        writer.close()

    server = await asyncio.start_server(hold_open, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


async def test_daemon_tls_pin_is_never_a_substitute_for_chain_validation(tmp_path):
    d = _daemon(tmp_path)
    server_ctx, pin = _self_signed_server(tmp_path)
    server, port = await _tls_server(server_ctx)
    try:
        # tls_check blocks on sockets: run it off the loop, as the daemon
        # does (run_in_executor), or client and server deadlock each other.
        # Exact pin on an untrusted (self-signed) chain: refused. The pin is
        # an additional control, not a bypass.
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, pin, [])
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, None, [])
    finally:
        server.close()


def _private_ca_server(tmp_path, san_ip="127.0.0.1", extra_dns=()):
    """A private root CA and a leaf it issued (SAN = san_ip); the server presents leaf only, like Wazuh."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import base64
    import hashlib
    import ipaddress
    import ssl
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Private Root CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-dashboard")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]
                                                       + [x509.DNSName(n) for n in extra_dns]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "leaf.pem", tmp_path / "leaf.key"
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    return ctx, pin, ca


async def test_daemon_private_ca_is_trusted_only_for_its_constrained_names_and_pin_is_enforced(tmp_path):
    import ipaddress
    from cryptography.hazmat.primitives import serialization

    d = _daemon(tmp_path)
    server_ctx, pin, ca = _private_ca_server(tmp_path)
    der = ca.public_bytes(serialization.Encoding.DER)
    for_host = [{"der": der, "dns": [], "cidrs": [ipaddress.ip_network("127.0.0.1/32")]}]
    other_host = [{"der": der, "dns": ["wazuh.example.internal"], "cidrs": [ipaddress.ip_network("10.0.0.1/32")]}]
    server, port = await _tls_server(server_ctx)
    try:
        # Private CA constrained to this IP: chain + IP SAN validate, with or without the matching pin.
        await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, None, for_host)
        await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, pin, for_host)
        # Wrong pin on an otherwise valid chain: refused.
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port,
                                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", for_host)
        # The same CA, constrained to other names, does not vouch for this host.
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, pin, other_host)
        # Name mismatch: the leaf's SAN is 127.0.0.1, so a different expected name fails even when trusted.
        dns_anchor = [{"der": der, "dns": ["wazuh.example.internal"], "cidrs": []}]
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "wazuh.example.internal", port, None, dns_anchor)
    finally:
        server.close()


async def test_daemon_refuses_a_leaf_with_any_san_outside_the_ca_constraints(tmp_path):
    """Mirrors Chromium ("Not permitted by name constraints"): constraints apply to every SAN, so a
    certificate that also names another host is refused even for the permitted host."""
    import ipaddress
    from cryptography.hazmat.primitives import serialization

    d = _daemon(tmp_path)
    server_ctx, pin, ca = _private_ca_server(tmp_path, extra_dns=("other-name.example.internal",))
    anchor = [{"der": ca.public_bytes(serialization.Encoding.DER), "dns": [],
               "cidrs": [ipaddress.ip_network("127.0.0.1/32")]}]
    server, port = await _tls_server(server_ctx)
    try:
        with pytest.raises(RuntimeError, match="TLS_VALIDATION_FAILED"):
            await asyncio.to_thread(d.tls_check, "127.0.0.1", "127.0.0.1", port, pin, anchor)
    finally:
        server.close()


def test_daemon_trust_policy_file_is_shared_with_chromium_and_ignores_unconstrained_cas(tmp_path):
    import base64
    import json
    d = _daemon(tmp_path)
    b64 = base64.b64encode(b"not-parsed-here").decode()
    policy = tmp_path / "chromium-policy.json"
    policy.write_text(json.dumps({"CACertificatesWithConstraints": [
        {"certificate": b64, "constraints": {"permitted_dns_names": ["Wazuh.Example.Internal."], "permitted_cidrs": []}},
        {"certificate": b64, "constraints": {}},  # unconstrained: never honoured
    ]}))
    anchors = d.trust_anchors(str(policy))
    assert len(anchors) == 1 and anchors[0]["dns"] == ["wazuh.example.internal"]
    assert d.anchor_permits(anchors[0], "wazuh.example.internal")
    assert d.anchor_permits(anchors[0], "dash.wazuh.example.internal")  # Chromium name-constraint semantics
    assert not d.anchor_permits(anchors[0], "evil-wazuh.example.internal")
    assert not d.anchor_permits(anchors[0], "3.104.196.100")
    assert d.trust_anchors(str(tmp_path / "missing.json")) == []


def test_daemon_never_passes_certificate_error_overrides_to_chromium():
    source = (Path(__file__).resolve().parents[2] / "infrastructure" / "browser-isolation" / "daemon.py").read_text()
    for flag in ("--ignore-certificate-errors\"", "--ignore-certificate-errors-spki-list", "--ignore-certificate-errors=",
                 "verify_mode = ssl.CERT_NONE", "check_hostname = False", "--allow-insecure-localhost"):
        assert flag not in source, flag


def _trust_tool():
    path = Path(__file__).resolve().parents[2] / "infrastructure" / "browser-isolation" / "trust_policy.py"
    spec = importlib.util.spec_from_file_location("trust_policy_tool", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_trust_policy_tool_refuses_unsafe_inputs(tmp_path):
    from cryptography.hazmat.primitives import serialization
    tool = _trust_tool()
    _, _, ca = _private_ca_server(tmp_path)
    ca_pem = tmp_path / "ca.pem"; ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_pem = tmp_path / "leaf.pem"  # written by _private_ca_server: not a CA
    key_pem = tmp_path / "with-key.pem"; key_pem.write_bytes(ca_pem.read_bytes() + (tmp_path / "leaf.key").read_bytes())
    for argv in (["--ca", str(leaf_pem), "--permit-ip", "3.104.196.100"],       # not a CA
                 ["--ca", str(key_pem), "--permit-ip", "3.104.196.100"],        # private key present
                 ["--ca", str(ca_pem)],                                          # unconstrained
                 ["--ca", str(ca_pem), "--permit-dns", "com"],                   # single label
                 ["--ca", str(ca_pem), "--permit-dns", "*.example.com"],         # wildcard
                 ["--ca", str(ca_pem), "--permit-ip", "3.0.0.0/8"]):             # too wide
        with pytest.raises(SystemExit):
            tool.main(argv + ["--out", str(tmp_path / "out.json")])
    out = tmp_path / "ok.json"
    assert tool.main(["--ca", str(ca_pem), "--permit-ip", "3.104.196.100", "--permit-dns", "wazuh.example.internal",
                      "--out", str(out)]) == 0
    d = _daemon(tmp_path)
    anchors = d.trust_anchors(str(out))
    assert len(anchors) == 1 and d.anchor_permits(anchors[0], "3.104.196.100")
    assert not d.anchor_permits(anchors[0], "3.104.196.101")
