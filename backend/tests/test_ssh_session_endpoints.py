"""
Security regression tests for Member 10 SSH backend foundation:
authentication, RBAC per role, object-level authorization (IDOR -> 404),
protocol validation, target availability, JIT grant validation,
fail-closed credential retrieval, safe failure states, and truthful
orchestration state transitions (no fake ACTIVE sessions).
"""

import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.api.v1.ssh_sessions import get_credential_service
from app.core.config import settings
from app.main import app
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.secret_providers import MockSecretProvider
from app.services.credential_service import CredentialService
from app.services.ssh_gateway import (
    SSHError,
    SSHGatewayConnection,
    get_ssh_gateway,
)
from tests.conftest import auth_header
from tests.test_credential_service import _scenario

SSH_PATH = "securepam/assets/linux-dev-01"
CANARY = "SSH-SECRET-CANARY-not-real"
NIL = "00000000-0000-0000-0000-000000000000"


async def _user(db, username: str) -> User:
    return (await db.execute(select(User).where(User.username == username))).scalar_one()


async def _asset(db, name: str) -> Asset:
    return (await db.execute(select(Asset).where(Asset.name == name))).scalar_one()


async def _actions(db, action: str) -> list[AuditLog]:
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


def _launch_body(req) -> dict:
    return {"request_id": str(req.access_request_id), "asset_id": str(req.asset_id)}


async def _ssh_ready(
    db,
    *,
    username="operator",
    asset_name="LINUX-DEV-01",
    request_status="ACTIVE",
    grant_status="ACTIVE",
    expires_in_minutes=30,
    with_ref=True,
):
    return await _scenario(
        db,
        username=username,
        asset_name=asset_name,
        protocol="SSH",
        request_status=request_status,
        grant_status=grant_status,
        expires_in_minutes=expires_in_minutes,
        ref_path=SSH_PATH,
        with_ref=with_ref,
    )


class MockFailingSSHGateway:
    async def prepare(self, *, session, asset, credential):
        raise SSHError("Transport failed to initialize")


class MockCrashingSSHGateway:
    async def prepare(self, *, session, asset, credential):
        raise RuntimeError("Unexpected gateway internal failure")


class MockConnectedSSHGateway:
    async def prepare(self, *, session, asset, credential):
        if credential.is_wiped:
            raise SSHError("Credential was wiped")
        return SSHGatewayConnection(
            protocol="ssh",
            hostname=asset.hostname,
            port=asset.port,
            gateway_session_id="gw-ssh-live-123",
            is_connected=True,
        )


@pytest.fixture
def provider():
    """Route CredentialService to a fake provider for SSH tests."""
    p = MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}})
    app.dependency_overrides[get_credential_service] = lambda: CredentialService(provider=p)
    yield p
    app.dependency_overrides.pop(get_credential_service, None)



@pytest.fixture(autouse=True)
def _recording_storage(tmp_path, monkeypatch):
    """Recordings go to a writable per-test directory (the default /data path is not)."""
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(tmp_path / "recordings"))


# --- Authentication & RBAC --------------------------------------------------

async def test_unauthenticated_ssh_launch_rejected(client):
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        json={"request_id": NIL, "asset_id": NIL},
    )
    assert r.status_code == 401


async def test_approver_cannot_launch_ssh(client, db_session, approver_token, provider):
    req = await _ssh_ready(db_session)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(approver_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403


async def test_auditor_cannot_launch_ssh(client, db_session, auditor_token, provider):
    req = await _ssh_ready(db_session)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(auditor_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403


# --- Validation: Target, Protocol & Request Scope ----------------------------

async def test_launch_non_ssh_target_rejected(client, db_session, operator_token, provider):
    # Request against Windows RDP asset must fail with 422
    rdp_asset = await _asset(db_session, "WIN-DEV-01")
    req = await _ssh_ready(db_session)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json={"request_id": str(req.access_request_id), "asset_id": str(rdp_asset.id)},
    )
    assert r.status_code == 422


async def test_launch_request_target_mismatch_rejected(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    other_ssh = await _asset(db_session, "LINUX-PROD-01")
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json={"request_id": str(req.access_request_id), "asset_id": str(other_ssh.id)},
    )
    assert r.status_code == 422


async def test_launch_unknown_asset_404(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json={"request_id": str(req.access_request_id), "asset_id": NIL},
    )
    assert r.status_code == 404


async def test_launch_soft_deleted_asset_404(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.is_deleted = True
    await db_session.commit()

    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 404


async def test_launch_with_another_users_request_is_404(client, db_session, operator2_token, provider):
    req = await _ssh_ready(db_session)  # Owned by operator
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator2_token),
        json=_launch_body(req),
    )
    assert r.status_code == 404
    assert provider.reads == []


async def test_launch_rejects_client_supplied_identity(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    peer = await _user(db_session, "admin")
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json={**_launch_body(req), "user_id": str(peer.id)},
    )
    assert r.status_code == 422


# --- Availability & JIT Validation -------------------------------------------

async def test_launch_disabled_target_denied(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.enabled = False
    await db_session.commit()

    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    assert provider.reads == []
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "ASSET_DISABLED"


async def test_launch_maintenance_asset_denied(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.status = "MAINTENANCE"
    await db_session.commit()

    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "ASSET_DISABLED"


async def test_launch_inactive_request_denied(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session, request_status="CANCELLED")
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "ACCESS_REQUEST_NOT_ACTIVE"


async def test_launch_unapproved_request_denied(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session, request_status="PENDING_APPROVAL")
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "ACCESS_REQUEST_NOT_ACTIVE"


@pytest.mark.parametrize("grant_status", ["REVOKED", "EXPIRED"])
async def test_launch_without_live_grant_denied(client, db_session, operator_token, provider, grant_status):
    req = await _ssh_ready(db_session, grant_status=grant_status)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    assert (await db_session.execute(select(Session))).scalars().all() == []
    assert provider.reads == []
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "NO_VALID_JIT_GRANT"


async def test_launch_with_lapsed_grant_denied_and_grant_expired(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session, expires_in_minutes=-1)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    grant = await db_session.get(JITGrant, req.jit_grant_id)
    await db_session.refresh(grant)
    assert grant.status == "EXPIRED"


# --- Safe Failure States (Fail-Closed) ---------------------------------------

async def test_launch_without_credential_reference_fails_closed(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session, with_ref=False)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 403
    (s,) = (await db_session.execute(select(Session))).scalars().all()
    assert s.status == "FAILED"
    (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
    assert failed.details["reason"] == "NO_CREDENTIAL_REFERENCE"


async def test_launch_provider_unavailable_fails_closed(client, db_session, operator_token, provider):
    provider.available = False
    req = await _ssh_ready(db_session)
    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 503
    (s,) = (await db_session.execute(select(Session))).scalars().all()
    assert s.status == "FAILED"
    (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
    assert failed.details["reason"] == "PROVIDER_UNAVAILABLE"


async def test_launch_gateway_error_fails_closed(client, db_session, operator_token, provider):
    app.dependency_overrides[get_ssh_gateway] = lambda: MockFailingSSHGateway()
    try:
        req = await _ssh_ready(db_session)
        r = await client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json=_launch_body(req),
        )
        assert r.status_code == 502
        (s,) = (await db_session.execute(select(Session))).scalars().all()
        assert s.status == "FAILED"
        (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
        assert failed.details["reason"] == "GATEWAY_ERROR"
    finally:
        app.dependency_overrides.pop(get_ssh_gateway, None)


async def test_launch_unexpected_error_fails_closed_without_orphaned_session(
    client, db_session, operator_token, provider
):
    app.dependency_overrides[get_ssh_gateway] = lambda: MockCrashingSSHGateway()
    try:
        req = await _ssh_ready(db_session)
        r = await client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json=_launch_body(req),
        )
        assert r.status_code == 500
        (s,) = (await db_session.execute(select(Session))).scalars().all()
        assert s.status == "FAILED"
        assert s.end_time is not None
        (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
        assert failed.details["reason"] == "UNEXPECTED_LAUNCH_ERROR"
    finally:
        app.dependency_overrides.pop(get_ssh_gateway, None)


# --- Successful Orchestration & Truthful State Transitions -------------------

async def test_successful_ssh_launch_orchestration_with_pending_gateway(
    client, db_session, operator_token, provider, monkeypatch
):
    """
    With the default PendingSSHGateway, the launch succeeds and prepares the session,
    but does NOT falsely mark the session ACTIVE or the recording RECORDING.
    """
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.recording_required = True
    await db_session.commit()

    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 201
    body = r.json()

    # Returned metadata is non-secret, enforces gateway mediation, and reflects STARTING state
    assert body["status"] == "STARTING"
    assert body["connection"]["mode"] == "GATEWAY_MEDIATED"
    assert body["connection"]["protocol"] == "ssh"
    assert body["connection"]["target_asset"] == "LINUX-DEV-01"
    # The internal address is never sent to the browser.
    assert "target_host" not in body["connection"] and "linux-dev-01.internal" not in r.text
    assert body["connection"]["direct_access_allowed"] is False
    assert body["connection"]["is_connected"] is False
    assert "direct connections to the target are not permitted" in body["connection"]["message"]
    assert "password" not in body and "private_key" not in body and "secret" not in body

    # Database Session row verification
    s = await db_session.get(Session, uuid.UUID(body["session_id"]))
    assert s.user_id == req.user_id
    assert s.asset_id == req.asset_id
    assert s.request_id == req.access_request_id
    assert s.jit_grant_id == req.jit_grant_id
    assert s.status == "STARTING"
    assert s.start_time is None  # Connection has not yet been established live

    # Database Recording row verification
    rec = await db_session.get(Recording, uuid.UUID(body["recording_id"]))
    assert rec.recording_type == "TERMINAL"
    assert rec.status == "PENDING"  # Recording has not yet begun
    assert rec.file_path.endswith(".cast")
    assert rec.file_path.startswith(settings.RECORDING_STORAGE_PATH)

    # Auditing: session prepared, credential retrieved, secret never leaked
    (prepared,) = await _actions(db_session, "SESSION_PREPARED")
    assert prepared.actor_username == "operator" and prepared.session_id == s.id
    (retrieved,) = await _actions(db_session, "CREDENTIAL_RETRIEVED")
    assert retrieved.session_id == s.id

    for row in (await db_session.execute(select(AuditLog))).scalars().all():
        assert CANARY not in repr(row.details)


async def test_successful_ssh_launch_without_recording(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.recording_required = False
    access_request = await db_session.get(AccessRequest, req.access_request_id)
    access_request.recording_required = False
    await db_session.commit()

    r = await client.post(
        "/api/v1/sessions/ssh/launch",
        headers=auth_header(operator_token),
        json=_launch_body(req),
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "STARTING"
    assert body["recording_id"] is None

    s = await db_session.get(Session, uuid.UUID(body["session_id"]))
    assert s.recording_id is None


async def test_connected_gateway_transitions_session_to_active(
    client, db_session, operator_token, provider, monkeypatch
):
    """
    When a gateway indicates that a real upstream connection was established,
    the session transitions to ACTIVE. However, because terminal stream capture
    is not yet integrated (pending Member 12), the recording truthfully remains PENDING
    rather than falsely asserting RECORDING.
    """
    app.dependency_overrides[get_ssh_gateway] = lambda: MockConnectedSSHGateway()
    try:
        req = await _ssh_ready(db_session)
        asset = await db_session.get(Asset, req.asset_id)
        asset.recording_required = True
        await db_session.commit()

        r = await client.post(
            "/api/v1/sessions/ssh/launch",
            headers=auth_header(operator_token),
            json=_launch_body(req),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "ACTIVE"
        assert body["connection"]["mode"] == "GATEWAY_MEDIATED"
        assert body["connection"]["is_connected"] is True
        assert body["connection"]["direct_access_allowed"] is False
        assert body["connection"]["gateway_session_id"] == "gw-ssh-live-123"
        assert "connected via SecurePAM Gateway" in body["connection"]["message"]

        s = await db_session.get(Session, uuid.UUID(body["session_id"]))
        assert s.status == "ACTIVE"
        assert s.start_time is not None
        assert s.gateway_session_id == "gw-ssh-live-123"

        rec = await db_session.get(Recording, uuid.UUID(body["recording_id"]))
        # Truthful recording status: even with is_connected=True, recording capture
        # is not yet integrated in Member 10, so status remains PENDING (never RECORDING).
        assert rec.status == "PENDING"

        (started,) = await _actions(db_session, "SESSION_STARTED")
        assert started.session_id == s.id
    finally:
        app.dependency_overrides.pop(get_ssh_gateway, None)




# --- Recording required but storage unavailable: refused ------------------

@pytest.fixture
def unwritable_storage(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(locked / "recordings"))
    yield
    locked.chmod(0o700)


async def test_launch_refused_when_recording_required_but_storage_unavailable(
    client, db_session, operator_token, provider, unwritable_storage
):
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.recording_required = True
    await db_session.commit()
    sessions_before = len((await db_session.execute(select(Session))).scalars().all())

    r = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
    assert "requires session recording" in r.json()["detail"]
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "RECORDING_UNAVAILABLE"
    assert len((await db_session.execute(select(Session))).scalars().all()) == sessions_before


async def test_launch_refused_when_request_requires_recording_and_storage_unavailable(
    client, db_session, operator_token, provider, unwritable_storage
):
    req = await _ssh_ready(db_session)
    access_request = await db_session.get(AccessRequest, req.access_request_id)
    access_request.recording_required = True
    await db_session.commit()
    r = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
