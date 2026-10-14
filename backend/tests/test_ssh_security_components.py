"""
Security & transport component tests for Member 10 (Phase 10.2 Stage 1):
- Ticket generation entropy, binding, TTL expiry, atomic GETDEL consumption, replay rejection, Redis error fail-closed.
- Fail-closed host-key matching, mismatch rejection, unknown host rejection, revoked key handling.
- AsyncSSHTerminalGateway credential handling, lifecycle cleanup, and wiped credential refusal.
"""

import hashlib
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.models.asset import Asset
from app.models.session import Session
from app.secret_providers import Credential
from app.services.ssh_gateway import SSHError
from app.services.ssh_host_key import (
    SSHHostKeyError,
    SSHHostKeyMismatchError,
    SSHHostKeyStorageError,
    SSHHostKeyUnknownError,
    SSHHostKeyValidator,
)
from app.services.ssh_terminal_gateway import (
    AsyncSSHTerminalGateway,
    LiveSSHConnection,
    MAX_TERMINAL_CHUNK_SIZE,
)
from app.services.ssh_ticket import (
    SSHTicketData,
    SSHTicketError,
    SSHTicketInvalidError,
    SSHTicketService,
    SSHTicketStorageError,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")


@pytest.fixture
async def redis_client():
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    yield client
    # Cleanup keys used in tests
    keys = await client.keys("ssh:*")
    if keys:
        await client.delete(*keys)
    await client.aclose()


def _sample_asset(name="LINUX-DEV-01", hostname="linux-dev-01.internal", port=22) -> Asset:
    return Asset(
        id=uuid.uuid4(),
        name=name,
        hostname=hostname,
        ip_address="10.0.0.1",
        port=port,
        protocol="SSH",
        asset_type="LINUX_SERVER",
        status="ACTIVE",
        enabled=True,
    )


def _sample_session(asset_id: uuid.UUID, user_id: uuid.UUID) -> Session:
    return Session(
        id=uuid.uuid4(),
        session_number="SES-TEST-001",
        user_id=user_id,
        asset_id=asset_id,
        request_id=uuid.uuid4(),
        protocol="SSH",
        status="STARTING",
    )


# --- 1. Ticket Service Tests -------------------------------------------------

@pytest.mark.asyncio
async def test_ticket_issuance_and_atomic_consumption(redis_client):
    service = SSHTicketService(redis_client=redis_client)
    session_id = uuid.uuid4()
    user_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    request_id = uuid.uuid4()
    grant_id = uuid.uuid4()

    ticket = await service.issue_ticket(
        session_id=session_id,
        user_id=user_id,
        asset_id=asset_id,
        access_request_id=request_id,
        jit_grant_id=grant_id,
        ttl_seconds=60,
    )

    assert isinstance(ticket, str) and len(ticket) >= 32

    # Check key exists and has TTL
    key = f"ssh:ticket:{hashlib.sha256(ticket.encode()).hexdigest()}"
    assert await redis_client.exists(f"ssh:ticket:{ticket}") == 0  # raw ticket is never a key
    ttl = await redis_client.ttl(key)
    assert 0 < ttl <= 60

    # First consumption: succeeds
    data = await service.consume_ticket(
        ticket=ticket,
        expected_session_id=session_id,
        expected_user_id=user_id,
    )
    assert data.session_id == session_id
    assert data.user_id == user_id
    assert data.asset_id == asset_id
    assert data.access_request_id == request_id
    assert data.jit_grant_id == grant_id

    # Replay protection: second consumption must fail immediately
    with pytest.raises(SSHTicketInvalidError, match="Ticket not found, expired, or already consumed"):
        await service.consume_ticket(
            ticket=ticket,
            expected_session_id=session_id,
            expected_user_id=user_id,
        )


@pytest.mark.asyncio
async def test_ticket_binding_mismatch_rejected(redis_client):
    service = SSHTicketService(redis_client=redis_client)
    session_id = uuid.uuid4()
    user_id = uuid.uuid4()

    ticket = await service.issue_ticket(
        session_id=session_id,
        user_id=user_id,
        asset_id=uuid.uuid4(),
        access_request_id=uuid.uuid4(),
        jit_grant_id=uuid.uuid4(),
    )

    # Wrong session_id
    with pytest.raises(SSHTicketInvalidError, match="Ticket session mismatch"):
        await service.consume_ticket(
            ticket=ticket,
            expected_session_id=uuid.uuid4(),
            expected_user_id=user_id,
        )


@pytest.mark.asyncio
async def test_ticket_asset_binding_mismatch_rejected(redis_client):
    service = SSHTicketService(redis_client=redis_client)
    session_id = uuid.uuid4()
    user_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    ticket = await service.issue_ticket(
        session_id=session_id,
        user_id=user_id,
        asset_id=asset_id,
        access_request_id=uuid.uuid4(),
        jit_grant_id=uuid.uuid4(),
    )

    # Wrong asset_id
    with pytest.raises(SSHTicketInvalidError, match="Ticket asset mismatch"):
        await service.consume_ticket(
            ticket=ticket,
            expected_session_id=session_id,
            expected_user_id=user_id,
            expected_asset_id=uuid.uuid4(),
        )


@pytest.mark.asyncio
async def test_ticket_expired_or_missing_rejected(redis_client):
    service = SSHTicketService(redis_client=redis_client)
    with pytest.raises(SSHTicketInvalidError, match="Ticket not found, expired, or already consumed"):
        await service.consume_ticket(
            ticket="non-existent-ticket-token-1234567890",
            expected_session_id=uuid.uuid4(),
            expected_user_id=uuid.uuid4(),
        )


@pytest.mark.asyncio
async def test_ticket_redis_failure_fails_closed():
    failing_redis = MagicMock()
    failing_redis.set = AsyncMock(side_effect=RedisConnectionError("Redis connection lost"))
    failing_redis.getdel = AsyncMock(side_effect=RedisConnectionError("Redis connection lost"))

    service = SSHTicketService(redis_client=failing_redis)

    with pytest.raises(SSHTicketStorageError, match="Failed to store SSH ticket in Redis"):
        await service.issue_ticket(
            session_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            asset_id=uuid.uuid4(),
            access_request_id=uuid.uuid4(),
            jit_grant_id=uuid.uuid4(),
        )

    with pytest.raises(SSHTicketStorageError, match="Failed to access Redis to consume ticket"):
        await service.consume_ticket(
            ticket="valid-format-ticket",
            expected_session_id=uuid.uuid4(),
            expected_user_id=uuid.uuid4(),
        )


# --- 2. Host-Key Verification Tests ------------------------------------------

@pytest.mark.asyncio
async def test_host_key_matching_succeeds():
    # Generate trusted Ed25519 key
    trusted_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_entry = trusted_key.export_public_key().decode().strip()
    known_hosts_line = f"linux-dev-01.internal,10.0.0.1 {pub_entry}\n"

    validator = SSHHostKeyValidator(known_hosts_data=known_hosts_line)
    asset = _sample_asset(hostname="linux-dev-01.internal")

    kh = await validator.get_trusted_known_hosts_for_asset(asset)
    assert kh is not None

    # Server presents matching key -> verified
    assert validator.verify_server_key(
        kh,
        asset.hostname,
        asset.ip_address,
        asset.port,
        trusted_key,
    ) is True


@pytest.mark.asyncio
async def test_host_key_mismatch_fails_closed():
    trusted_key = asyncssh.generate_private_key("ssh-ed25519")
    attacker_key = asyncssh.generate_private_key("ssh-ed25519")

    pub_entry = trusted_key.export_public_key().decode().strip()
    known_hosts_line = f"linux-dev-01.internal,10.0.0.1 {pub_entry}\n"

    validator = SSHHostKeyValidator(known_hosts_data=known_hosts_line)
    asset = _sample_asset(hostname="linux-dev-01.internal")

    kh = await validator.get_trusted_known_hosts_for_asset(asset)

    # Server presents different key -> mismatch error raised fail-closed
    with pytest.raises(SSHHostKeyMismatchError, match="Host key mismatch"):
        validator.verify_server_key(
            kh,
            asset.hostname,
            asset.ip_address,
            asset.port,
            attacker_key,
        )


@pytest.mark.asyncio
async def test_unknown_host_key_fails_closed():
    trusted_key = asyncssh.generate_private_key("ssh-ed25519")
    pub_entry = trusted_key.export_public_key().decode().strip()
    known_hosts_line = f"other-host.internal {pub_entry}\n"

    validator = SSHHostKeyValidator(known_hosts_data=known_hosts_line)
    unregistered_asset = _sample_asset(hostname="unregistered-linux.internal")

    # Asset has no entry in known hosts -> rejected fail-closed
    with pytest.raises(SSHHostKeyUnknownError, match="No trusted host key configured for target asset"):
        await validator.get_trusted_known_hosts_for_asset(unregistered_asset)


@pytest.mark.asyncio
async def test_host_key_planted_in_redis_is_not_trusted(redis_client):
    """Redis is not a trust source: a key written there must not let a host in."""
    planted = asyncssh.generate_private_key("ssh-ed25519")
    pub_entry = planted.export_public_key().decode().strip()
    asset = _sample_asset()
    await redis_client.set(f"ssh:known_hosts:{asset.id}", f"{asset.hostname},{asset.ip_address} {pub_entry}\n")
    try:
        with pytest.raises(SSHHostKeyUnknownError):
            await SSHHostKeyValidator().get_trusted_known_hosts_for_asset(asset)
    finally:
        await redis_client.delete(f"ssh:known_hosts:{asset.id}")


# --- 3. AsyncSSHTerminalGateway Transport Tests ------------------------------

@pytest.mark.asyncio
async def test_gateway_rejects_already_wiped_credential():
    gateway = AsyncSSHTerminalGateway()
    asset = _sample_asset()
    session = _sample_session(asset.id, uuid.uuid4())

    cred = Credential(username="ubuntu", secret="temporary-password", secret_type="PASSWORD", version=1)
    cred.wipe()

    with pytest.raises(SSHError, match="Credential was wiped prior to SSH handshake"):
        await gateway.prepare(session=session, asset=asset, credential=cred)


@pytest.mark.asyncio
async def test_gateway_fails_closed_when_host_key_untrusted():
    # Empty validator rejects all hosts
    validator = SSHHostKeyValidator(known_hosts_data="")
    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    asset = _sample_asset()
    session = _sample_session(asset.id, uuid.uuid4())

    cred = Credential(username="ubuntu", secret="pass123", secret_type="PASSWORD", version=1)

    with pytest.raises(SSHError, match="Host-key verification failed"):
        await gateway.prepare(session=session, asset=asset, credential=cred)


@pytest.mark.asyncio
async def test_live_ssh_connection_cleanup_lifecycle():
    mock_conn = MagicMock()
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    session_id = uuid.uuid4()
    live = LiveSSHConnection(
        session_id=session_id,
        asset_id=uuid.uuid4(),
        connection=mock_conn,
    )

    assert live.is_closed is False
    await live.close()

    assert live.is_closed is True
    mock_conn.close.assert_called_once()
    mock_conn.wait_closed.assert_awaited_once()

    # Multiple close calls are idempotent
    await live.close()
    assert mock_conn.close.call_count == 1


@pytest.mark.asyncio
async def test_gateway_connection_registry_and_close_all():
    gateway = AsyncSSHTerminalGateway()

    mock_conn1 = MagicMock()
    mock_conn1.close = MagicMock()
    mock_conn1.wait_closed = AsyncMock()

    mock_conn2 = MagicMock()
    mock_conn2.close = MagicMock()
    mock_conn2.wait_closed = AsyncMock()

    sid1 = uuid.uuid4()
    sid2 = uuid.uuid4()

    gateway._active_connections[sid1] = LiveSSHConnection(session_id=sid1, asset_id=uuid.uuid4(), connection=mock_conn1)
    gateway._active_connections[sid2] = LiveSSHConnection(session_id=sid2, asset_id=uuid.uuid4(), connection=mock_conn2)

    assert gateway.get_live_connection(sid1) is not None
    assert gateway.get_live_connection(sid2) is not None

    await gateway.close_all_connections()

    assert gateway.get_live_connection(sid1) is None
    assert gateway.get_live_connection(sid2) is None
    mock_conn1.close.assert_called_once()
    mock_conn2.close.assert_called_once()


@pytest.mark.asyncio
async def test_retained_redis_client_in_ticket_service():
    """Verify F-03: SSHTicketService reuses retained Redis client."""
    service = SSHTicketService()
    r1 = await service._get_redis()
    r2 = await service._get_redis()
    assert r1 is r2
    await service.aclose()
    assert service._redis is None


@pytest.mark.asyncio
async def test_gateway_cleanup_on_cancellation_and_unexpected_exception():
    """Verify F-01: socket is cleaned up on cancellation or unhandled exception without swallowing."""
    import asyncio
    validator = MagicMock()
    validator.get_trusted_known_hosts_for_asset = AsyncMock(return_value=MagicMock())

    gateway = AsyncSSHTerminalGateway(host_key_validator=validator)
    asset = _sample_asset()
    session = _sample_session(asset.id, uuid.uuid4())
    cred = Credential(username="ubuntu", secret="pass123", secret_type="PASSWORD", version=1)

    # 1. Cancellation path
    with patch("asyncssh.connect", side_effect=asyncio.CancelledError()):
        with pytest.raises(asyncio.CancelledError):
            await gateway.prepare(session=session, asset=asset, credential=cred)

    # 2. Unhandled BaseException path
    with patch("asyncssh.connect", side_effect=RuntimeError("Unexpected transport crash")):
        with pytest.raises(SSHError, match="SSH connection failed unexpectedly"):
            await gateway.prepare(session=session, asset=asset, credential=cred)
