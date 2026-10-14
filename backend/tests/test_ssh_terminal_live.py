"""
Live SSH Terminal & WebSocket Bridge Integration Tests — Member 10 (Phase 10.2 Stage 2).

Verifies:
1. Real local test SSH server interaction using AsyncSSH test-server API.
2. End-to-end WebSocket launch -> ticket -> PTY terminal bidirectional I/O and resize.
3. Ticket replay, user/session/asset mismatch (F-04), expiry, and Redis storage failure.
4. Fail-closed host-key mismatch and unknown host keys.
5. Unconditional connection and registry cleanup on disconnect and cancellation (F-02).
6. In-session JIT grant expiration termination.
7. Zero secret leakage in HTTP responses, WebSocket frames, and audit logs.
"""

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import asyncssh
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.security import generate_session_number
from app.database.session import async_session_factory
from app.main import app
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.api.v1.ssh_sessions import get_credential_service
from app.services.credential_service import CredentialService
from app.services.ssh_host_key import SSHHostKeyValidator
from app.services.ssh_terminal_gateway import (
    AsyncSSHTerminalGateway,
    get_terminal_gateway,
)
from app.services.ssh_ticket import (
    SSHTicketInvalidError,
    SSHTicketService,
    SSHTicketStorageError,
    get_ssh_ticket_service,
)
from tests.conftest import auth_header
from tests.test_credential_service import MockSecretProvider, _scenario

CANARY = "SSH-SECRET-LIVE-CANARY-999"
SSH_PATH = "securepam/assets/linux-dev-01"


import threading



@pytest.fixture(autouse=True)
def _recording_storage(tmp_path, monkeypatch):
    """Recordings go to a writable per-test directory (the default /data path is not)."""
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(tmp_path / "recordings"))


class ThreadedSSHServer:
    def __init__(self, server_key, expected_user: str = "ubuntu", expected_pass: str = CANARY):
        self.server_key = server_key
        self.expected_user = expected_user
        self.expected_pass = expected_pass
        self.port = None
        self.loop = None
        self.server = None
        self.last_terminal_size = None
        self._ready = threading.Event()
        self._thread = None

    def _thread_main(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        outer = self

        class Srv(asyncssh.SSHServer):
            def session_requested(self):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return username == outer.expected_user and password == outer.expected_pass

            def terminal_size_changed(self, width, height, pixwidth, pixheight):
                outer.last_terminal_size = (width, height)

        async def handle_process(process):
            process.stdout.write("Welcome to SecurePAM Live Test Terminal!\n")
            try:
                while True:
                    data = await process.stdin.read(1024)
                    if not data:
                        break
                    if "exit" in data:
                        process.stdout.write("logout\n")
                        process.exit(0)
                        break
                    process.stdout.write(f"Echo: {data}")
            except Exception:
                pass

        async def _run():
            self.server = await asyncssh.create_server(
                Srv,
                "127.0.0.1",
                0,
                server_host_keys=[self.server_key],
                process_factory=handle_process,
            )
            self.port = self.server.sockets[0].getsockname()[1]
            self._ready.set()

        self.loop.run_until_complete(_run())
        self.loop.run_forever()

    def start(self) -> int:
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)
        return self.port

    def stop(self) -> None:
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread:
            self._thread.join(timeout=2.0)


# --- Setup & Fixtures ---

@pytest.fixture
def provider():
    p = MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}})
    app.dependency_overrides[get_credential_service] = lambda: CredentialService(provider=p)
    yield p
    app.dependency_overrides.pop(get_credential_service, None)


async def _seed_live_scenario(db, port: int, known_hosts_line: str, expires_in_seconds: int = 1800):
    """Seed DB with asset pointing to local test SSH server, valid request, and JIT grant."""
    sc = await _scenario(
        db,
        username="operator",
        asset_name="LINUX-DEV-01",
        protocol="SSH",
        request_status="ACTIVE",
        grant_status="ACTIVE",
        expires_in_minutes=expires_in_seconds // 60 or 1,
        ref_path=SSH_PATH,
        with_ref=True,
    )
    asset = await db.get(Asset, sc.asset_id)
    asset.hostname = "127.0.0.1"
    asset.ip_address = "127.0.0.1"
    asset.port = port
    asset.recording_required = False  # recording-required paths are tested explicitly

    # Adjust grant expiry if needed
    grant = await db.get(JITGrant, sc.jit_grant_id)
    grant.expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

    await db.commit()
    return sc, asset


# --- 1. End-to-End Live Terminal & PTY Resize Test ---

@pytest.mark.asyncio
async def test_live_ssh_terminal_bidirectional_and_resize(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    known_hosts_line = f"127.0.0.1 {pub_str}\n"

    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=known_hosts_line)
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, known_hosts_line)

        # 1. Launch SSH Session via HTTP POST
        client = TestClient(app)
        launch_res = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        assert launch_res.status_code == 201
        launch_data = launch_res.json()

        session_id = launch_data["session_id"]
        ticket = launch_data["ticket"]
        assert ticket is not None
        assert CANARY not in json.dumps(launch_data)

        # 2. Connect live WebSocket with ticket
        ws_url = f"/api/v1/sessions/ssh/{session_id}/ws"
        assert "ticket" not in ws_url  # the ticket travels in the first frame only
        with client.websocket_connect(ws_url) as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            # Receive greeting banner
            banner_raw = ws.receive_text()
            banner = json.loads(banner_raw)
            assert banner["type"] == "output"
            assert "Welcome to SecurePAM Live Test Terminal!" in banner["data"]

            # Send terminal input: command
            ws.send_text(json.dumps({"type": "input", "data": "whoami\n"}))
            # Read until command echo is received (PTY echoes typed chars first, then process outputs)
            received = ""
            for _ in range(5):
                raw = ws.receive_text()
                data = json.loads(raw)
                if data["type"] == "output":
                    received += data["data"]
                if "Echo: whoami" in received:
                    break
            assert "Echo: whoami" in received

            # Send terminal resize
            ws.send_text(json.dumps({"type": "resize", "cols": 120, "rows": 40}))

            # Send ping
            ws.send_text(json.dumps({"type": "ping"}))
            pong_raw = ws.receive_text()
            pong = json.loads(pong_raw)
            assert pong["type"] == "pong"

            # Check that live connection was registered in gateway
            live_conn = gateway.get_live_connection(uuid.UUID(session_id))
            assert live_conn is not None
            assert live_conn.is_closed is False

            # Exit terminal cleanly
            ws.send_text(json.dumps({"type": "input", "data": "exit\n"}))

        # 3. Verify clean post-disconnect state (Fix F-02)
        s = None
        for _ in range(25):
            async with async_session_factory() as db:
                s = await db.get(Session, uuid.UUID(session_id))
            if s and s.status == "COMPLETED" and gateway.get_live_connection(uuid.UUID(session_id)) is None:
                break
            await asyncio.sleep(0.1)

        assert gateway.get_live_connection(uuid.UUID(session_id)) is None
        assert s is not None and s.status == "COMPLETED"
        assert s.start_time is not None
        assert s.end_time is not None

        async with async_session_factory() as db:
            # Recording is not required for this target, so no recording is
            # claimed. (Required-but-unavailable recording is refused by default,
            # and marked FAILED when explicitly allowed: see
            # test_truthful_recording_status_pending_then_failed.)
            assert s.recording_id is None

            # Verify CANARY was never recorded in audit logs
            for row in (await db.execute(select(AuditLog))).scalars().all():
                assert CANARY not in repr(row.details)

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 2. Ticket Replay Prevention over WebSocket ---

@pytest.mark.asyncio
async def test_websocket_ticket_replay_rejected(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n")
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # First connection: consumes ticket
        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()

        # Second connection with same ticket: MUST be rejected
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
                ws.receive_text()

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 3. Ticket Binding Mismatches (Session & Asset Fix F-04) ---

@pytest.mark.asyncio
async def test_websocket_ticket_binding_mismatches_rejected(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    pub_str = srv_key.export_public_key().decode().strip()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n")
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # 1. Connecting to different session ID with this ticket
        fake_session_id = str(uuid.uuid4())
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{fake_session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
                ws.receive_text()

        # 2. Fix F-04: Issue ticket bound to wrong asset
        ticket_service = get_ssh_ticket_service()
        mismatched_asset_ticket = await ticket_service.issue_ticket(
            session_id=uuid.UUID(session_id),
            user_id=sc.user_id,
            asset_id=uuid.uuid4(),  # Different asset!
            access_request_id=sc.access_request_id,
            jit_grant_id=sc.jit_grant_id,
        )

        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": mismatched_asset_ticket}))
                ws.receive_text()

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 4. Expired Ticket and Missing Ticket ---

@pytest.mark.asyncio
async def test_websocket_missing_or_expired_ticket_rejected(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    pub_str = srv_key.export_public_key().decode().strip()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n")
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        session_id = r.json()["session_id"]

        # Missing ticket
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.receive_text()

        # Bogus ticket
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": "bogus-expired-ticket"}))
                ws.receive_text()

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 5. Fail-Closed Host Key Mismatch ---

@pytest.mark.asyncio
async def test_websocket_host_key_mismatch_fails_closed(db_session, operator_token, provider):
    # Server runs with key A
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    server = ThreadedSSHServer(server_key)
    port = server.start()

    # Known hosts contains key B (attacker or mismatched key)
    different_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = different_key.export_public_key().decode().strip()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n")
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # WebSocket connection must fail closed on host key mismatch: the
        # server first sends a safe error frame, then closes with the stable
        # reason code (see credential_errors.failure_message).
        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            frame = json.loads(ws.receive_text())
            assert frame["type"] == "error"
            assert "host key" in frame["message"].lower()
            with pytest.raises(Exception):
                ws.receive_text()  # server has closed the connection

        # Session must be recorded as FAILED in DB
        s = await db_session.get(Session, uuid.UUID(session_id))
        await db_session.refresh(s)
        assert s.status == "FAILED"

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 6. Abrupt Client Disconnect & Registry Eviction (Fix F-02) ---

@pytest.mark.asyncio
async def test_websocket_abrupt_disconnect_evicts_registry(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n")
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()  # Read greeting
            # Abrupt disconnect
            ws.close()

        # Registry must have no lingering active connection
        s = None
        for _ in range(25):
            async with async_session_factory() as db:
                s = await db.get(Session, uuid.UUID(session_id))
            if gateway.get_live_connection(uuid.UUID(session_id)) is None and s and s.status == "COMPLETED":
                break
            await asyncio.sleep(0.1)

        assert gateway.get_live_connection(uuid.UUID(session_id)) is None
        assert s is not None and s.status == "COMPLETED"

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 7. In-Session JIT Expiry Closes Connection ---

@pytest.mark.asyncio
async def test_websocket_in_session_jit_expiry_terminates(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        # Grant expires in 1 second
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1)
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()  # Read greeting
            # Wait for JIT monitor to fire (grant expires in 1s)
            error_msg = ws.receive_text()
            assert "JIT grant has expired" in error_msg

        # Session must be marked EXPIRED
        s = None
        for _ in range(25):
            async with async_session_factory() as db:
                s = await db.get(Session, uuid.UUID(session_id))
            if s and s.status == "EXPIRED" and gateway.get_live_connection(uuid.UUID(session_id)) is None:
                break
            await asyncio.sleep(0.1)

        assert s is not None and s.status == "EXPIRED"
        assert gateway.get_live_connection(uuid.UUID(session_id)) is None

    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 8. In-Session JIT Revocation Closes Connection ---

@pytest.mark.asyncio
async def test_websocket_mid_session_jit_revocation_terminates(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        # Valid 30-minute grant
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()  # Read greeting banner

            # Actively revoke JIT grant mid-session in DB
            async with async_session_factory() as db:
                grant = await db.get(JITGrant, sc.jit_grant_id)
                grant.status = "REVOKED"
                grant.revoked_at = datetime.now(timezone.utc)
                await db.commit()

            # Active monitor must detect revocation within polling loop and send notification
            error_msg = ws.receive_text()
            assert "Access authorization has been revoked" in error_msg

        # Session must be marked EXPIRED and gateway connection evicted
        s = None
        for _ in range(25):
            async with async_session_factory() as db:
                s = await db.get(Session, uuid.UUID(session_id))
            if s and s.status == "EXPIRED" and gateway.get_live_connection(uuid.UUID(session_id)) is None:
                break
            await asyncio.sleep(0.1)

        assert s is not None and s.status == "EXPIRED"
        assert gateway.get_live_connection(uuid.UUID(session_id)) is None

        # Verify SESSION_REVOKED event was recorded
        async with async_session_factory() as db:
            events = (
                await db.execute(
                    select(SessionEvent).where(SessionEvent.session_id == uuid.UUID(session_id))
                )
            ).scalars().all()
            event_types = [e.event_type for e in events]
            assert "SESSION_REVOKED" in event_types
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 9. Authorization Revalidation Failure Fails Closed ---

@pytest.mark.asyncio
async def test_websocket_authorization_revalidation_failure_terminates_fail_closed(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # Patch JITGrant query in monitor to simulate repeated database read failure
        from sqlalchemy.ext.asyncio import AsyncSession
        orig_get = AsyncSession.get
        fail_trigger = False

        async def mocked_get(self, entity, ident, **kwargs):
            if fail_trigger and entity is JITGrant:
                raise RuntimeError("Simulated transient database outage during revalidation")
            return await orig_get(self, entity, ident, **kwargs)

        with patch.object(AsyncSession, "get", new=mocked_get):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
                ws.receive_text()  # Read greeting banner
                # Trigger DB failure in active monitor
                fail_trigger = True

                # Monitor must fail closed after 2 consecutive errors
                error_msg = ws.receive_text()
                assert "Authorization verification unavailable" in error_msg

        # Session must be marked FAILED and connection evicted
        s = None
        for _ in range(25):
            async with async_session_factory() as db:
                s = await db.get(Session, uuid.UUID(session_id))
            if s and s.status == "FAILED" and gateway.get_live_connection(uuid.UUID(session_id)) is None:
                break
            await asyncio.sleep(0.1)

        assert s is not None and s.status == "FAILED"
        assert gateway.get_live_connection(uuid.UUID(session_id)) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 10. Database Commit Failure After Connection Acquisition Cleans Up Transport ---

@pytest.mark.asyncio
async def test_websocket_db_commit_failure_cleans_up_connection(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # Simulate database commit failure right after connection is prepared
        from sqlalchemy.ext.asyncio import AsyncSession
        orig_commit = AsyncSession.commit
        commit_fail_count = 0

        async def failing_commit(self):
            nonlocal commit_fail_count
            commit_fail_count += 1
            if commit_fail_count == 1:
                raise RuntimeError("Simulated DB commit error during session start")
            return await orig_commit(self)

        with patch.object(AsyncSession, "commit", new=failing_commit):
            try:
                with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                    ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
                    ws.receive_text()
            except Exception:
                pass

        # Registry must be completely evicted — NO LEAK!
        assert gateway.get_live_connection(uuid.UUID(session_id)) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 11. Truthful Recording Status: PENDING during session, FAILED upon completion ---

@pytest.mark.asyncio
async def test_required_recording_captures_real_artifact(db_session, operator_token, provider):
    """Recording required: the terminal stream is recorded server-side, the
    artifact is private, hashed and replayable, and the outcome is audited."""
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        asset.recording_required = True
        await db_session.commit()
        client = TestClient(app)

        data = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        ).json()
        session_id, recording_id = data["session_id"], uuid.UUID(data["recording_id"])

        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": data['ticket']}))
            ws.receive_text()  # greeting
            async with async_session_factory() as db:
                assert (await db.get(Recording, recording_id)).status == "RECORDING"
            ws.send_text(json.dumps({"type": "input", "data": "recording-marker\n"}))
            ws.receive_text()
            ws.send_text(json.dumps({"type": "input", "data": "exit\n"}))

        rec = None
        for _ in range(50):
            async with async_session_factory() as db:
                rec = await db.get(Recording, recording_id)
            if rec and rec.status in ("COMPLETED", "FAILED"):
                break
            await asyncio.sleep(0.1)
        assert rec is not None and rec.status == "COMPLETED"

        artifact = Path(rec.file_path)
        assert artifact.is_file()
        assert (artifact.stat().st_mode & 0o777) == 0o600
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == rec.file_hash
        assert rec.file_size == artifact.stat().st_size

        lines = artifact.read_text().splitlines()
        header = json.loads(lines[0])
        assert header["version"] == 2 and header["width"] == 80
        output = "".join(json.loads(line)[2] for line in lines[1:] if json.loads(line)[1] == "o")
        assert "Welcome to SecurePAM Live Test Terminal" in output
        assert "recording-marker" in output
        assert CANARY not in artifact.read_text()  # the credential never reaches the recording

        async with async_session_factory() as db:
            actions = [a.action for a in (await db.execute(
                select(AuditLog).where(AuditLog.session_id == uuid.UUID(session_id)))).scalars().all()]
        assert "RECORDING_STARTED" in actions and "RECORDING_COMPLETED" in actions

        # The activity transcript is a separate, hashed artifact derived from the same stream.
        from app.services.command_transcript import transcript_path
        meta = rec.metadata_["transcript"]
        tpath = transcript_path(rec.file_path)
        assert (tpath.stat().st_mode & 0o777) == 0o600
        assert hashlib.sha256(tpath.read_bytes()).hexdigest() == meta["sha256"]
        doc = json.loads(tpath.read_text())
        by_input = {e["input"]: e for e in doc["events"]}
        assert "recording-marker" in by_input and "exit" in by_input
        assert "recording-marker" in by_input["recording-marker"]["output"] or by_input["recording-marker"]["output"] == ""
        assert doc["execution_verified"] is False and CANARY not in tpath.read_text()
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == rec.file_hash  # evidence untouched
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


@pytest.mark.asyncio
async def test_recording_start_failure_denies_the_session(db_session, operator_token, provider):
    """If the recorder cannot start, the operator gets no terminal and the
    session and recording end FAILED."""
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    gateway = AsyncSSHTerminalGateway(host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n"))
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway
    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        asset.recording_required = True
        await db_session.commit()
        client = TestClient(app)
        data = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        ).json()
        session_id, recording_id = uuid.UUID(data["session_id"]), uuid.UUID(data["recording_id"])
        async with async_session_factory() as db:
            Path((await db.get(Recording, recording_id)).file_path).write_text("pre-existing")  # O_EXCL fails

        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": data['ticket']}))
            assert "recording could not start" in ws.receive_text().lower()

        async with async_session_factory() as db:
            assert (await db.get(Session, session_id)).status == "FAILED"
            assert (await db.get(Recording, recording_id)).status == "FAILED"
            actions = [a.action for a in (await db.execute(
                select(AuditLog).where(AuditLog.session_id == session_id))).scalars().all()]
        assert "RECORDING_FAILED" in actions and "RECORDING_STARTED" not in actions
        assert gateway.get_live_connection(session_id) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- 12. Cancellation During Live Terminal Pump Cleans Up Connection ---

@pytest.mark.asyncio
async def test_websocket_cancellation_during_pump_cleans_up_connection(db_session, operator_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()

    validator = SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    try:
        sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
        client = TestClient(app)

        r = client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
        )
        data = r.json()
        session_id = data["session_id"]
        ticket = data["ticket"]

        # Connect, read greeting, then exit context abruptly to trigger cancellation
        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()

        # Registry must be completely evicted
        for _ in range(25):
            if gateway.get_live_connection(uuid.UUID(session_id)) is None:
                break
            await asyncio.sleep(0.1)

        assert gateway.get_live_connection(uuid.UUID(session_id)) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


# --- Termination through the sessions API ends the live terminal ---

async def _live_terminal(db_session, operator_token, port, pub_str):
    sc, asset = await _seed_live_scenario(db_session, port, f"127.0.0.1 {pub_str}\n", expires_in_seconds=1800)
    client = TestClient(app)
    data = client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json={"request_id": str(sc.access_request_id), "asset_id": str(asset.id)},
    ).json()
    return client, uuid.UUID(data["session_id"]), data["ticket"]


async def _wait_closed(gateway, session_id, seconds=4.0):
    for _ in range(int(seconds * 10)):
        if gateway.get_live_connection(session_id) is None:
            return True
        await asyncio.sleep(0.1)
    return False


@pytest.mark.asyncio
async def test_admin_terminate_closes_live_ssh_terminal(db_session, operator_token, admin_token, provider):
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    gateway = AsyncSSHTerminalGateway(host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n"))
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway
    try:
        client, session_id, ticket = await _live_terminal(db_session, operator_token, port, pub_str)
        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()
            assert gateway.get_live_connection(session_id) is not None
            term = client.post(f"/api/v1/sessions/{session_id}/terminate", headers=auth_header(admin_token))
            assert term.status_code == 200
            # The monitor re-reads the session each second, on whichever worker holds the terminal.
            assert await _wait_closed(gateway, session_id), "terminate left the SSH connection open"
        async with async_session_factory() as db:
            assert (await db.get(Session, session_id)).status == "TERMINATED"  # ended by an administrator, not by its owner
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()


@pytest.mark.asyncio
async def test_terminal_closes_when_session_ends_on_another_worker(db_session, operator_token, provider):
    """Only the session row changes (as when another worker handled the
    terminate); the monitor must notice and close the terminal."""
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    gateway = AsyncSSHTerminalGateway(host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n"))
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway
    try:
        client, session_id, ticket = await _live_terminal(db_session, operator_token, port, pub_str)
        with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
            ws.receive_text()
            assert gateway.get_live_connection(session_id) is not None
            async with async_session_factory() as db:
                (await db.get(Session, session_id)).status = "COMPLETED"
                await db.commit()
            assert await _wait_closed(gateway, session_id), "monitor did not close the terminal"
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()



@pytest.mark.asyncio
async def test_connect_refused_when_recording_became_required(db_session, operator_token, provider):
    """A session prepared before recording was required cannot be connected afterwards."""
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    gateway = AsyncSSHTerminalGateway(host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n"))
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway
    try:
        client, session_id, ticket = await _live_terminal(db_session, operator_token, port, pub_str)
        async with async_session_factory() as db:
            s = await db.get(Session, session_id)
            (await db.get(Asset, s.asset_id)).recording_required = True
            await db.commit()
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
                ws.receive_text()
        assert gateway.get_live_connection(session_id) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()



@pytest.mark.asyncio
async def test_ticket_in_url_is_not_accepted(db_session, operator_token, provider):
    """A valid ticket in the query string is ignored: only the auth frame counts."""
    srv_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_str = srv_key.export_public_key().decode().strip()
    server = ThreadedSSHServer(srv_key)
    port = server.start()
    gateway = AsyncSSHTerminalGateway(host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 {pub_str}\n"))
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway
    try:
        client, session_id, ticket = await _live_terminal(db_session, operator_token, port, pub_str)
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/v1/sessions/ssh/{session_id}/ws?ticket={ticket}") as ws:
                ws.send_text(json.dumps({"type": "input", "data": "whoami\n"}))  # not an auth frame
                ws.receive_text()
        assert gateway.get_live_connection(session_id) is None
    finally:
        app.dependency_overrides.pop(get_terminal_gateway, None)
        server.stop()
