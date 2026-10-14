"""
SSH Ephemeral Ticket Service — SecurePAM Member 10 (SSH Gateway).

Generates single-use, high-entropy connection tickets stored in Redis with an
enforced 60-second time-to-live (TTL).

Security Controls:
- Generation: 256-bit cryptographic entropy via `secrets.token_urlsafe(32)`.
- Binding: Bound strictly to session_id, user_id, asset_id, request_id, and jit_grant_id.
- Single-Use & Replay Protection: Atomic consumption via Redis `GETDEL`.
  Subsequent requests return nil and are rejected.
- Expiration: Strict 60-second TTL (EX 60). Expired tickets are rejected.
- Secret Hygiene: SSH passwords, private keys, or long-lived tokens are NEVER stored in tickets.
- Fail-Closed: If Redis is unreachable, operations raise SSHTicketStorageError rather
  than proceeding in an unverified state.
"""

import asyncio
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import settings


class SSHTicketError(Exception):
    """Base exception for SSH ticket operations."""


class SSHTicketStorageError(SSHTicketError):
    """Redis or storage backend is unavailable (fail-closed)."""


class SSHTicketInvalidError(SSHTicketError):
    """Ticket was missing, expired, reused, or bound to a different session/user."""


@dataclass(frozen=True)
class SSHTicketData:
    """Deserialized, validated ticket payload."""

    ticket: str
    session_id: uuid.UUID
    user_id: uuid.UUID
    asset_id: uuid.UUID
    access_request_id: uuid.UUID
    jit_grant_id: uuid.UUID
    created_at: str


class SSHTicketService:
    DEFAULT_TTL_SECONDS: int = 60
    KEY_PREFIX: str = "ssh:ticket:"

    def __init__(self, redis_client: Optional[aioredis.Redis] = None) -> None:
        self._redis = redis_client
        self._injected = redis_client is not None
        self._loop = None

    async def _get_redis(self) -> aioredis.Redis:
        if self._injected and self._redis is not None:
            return self._redis

        current_loop = asyncio.get_running_loop()
        if self._redis is not None and self._loop is current_loop:
            return self._redis

        # Either not yet initialized or event loop was recreated across tests
        if self._redis is not None and not self._injected:
            try:
                await self._redis.aclose()
            except Exception:
                pass
        self._redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        self._loop = current_loop
        return self._redis

    async def aclose(self) -> None:
        """Close retained Redis client connection pool if locally created."""
        if self._redis is not None and not self._injected:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None
            self._loop = None

    def _ticket_key(self, ticket: str) -> str:
        # Keyed by SHA-256 of the ticket, never the ticket itself, so reading
        # Redis (e.g. SCAN ssh:ticket:*) does not reveal a usable ticket.
        return f"{self.KEY_PREFIX}{hashlib.sha256(ticket.encode('utf-8')).hexdigest()}"

    async def issue_ticket(
        self,
        *,
        session_id: uuid.UUID,
        user_id: uuid.UUID,
        asset_id: uuid.UUID,
        access_request_id: uuid.UUID,
        jit_grant_id: uuid.UUID,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> str:
        """
        Issue a high-entropy, single-use ticket bound to this session and user.
        Fails closed with SSHTicketStorageError if Redis is unavailable.
        """
        if ttl_seconds <= 0:
            raise ValueError("Ticket TTL must be a positive integer.")

        ticket = secrets.token_urlsafe(32)
        key = self._ticket_key(ticket)
        payload = {
            "session_id": str(session_id),
            "user_id": str(user_id),
            "asset_id": str(asset_id),
            "access_request_id": str(access_request_id),
            "jit_grant_id": str(jit_grant_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            r = await self._get_redis()
            # Set key with exact expiry in seconds
            await r.set(key, json.dumps(payload), ex=ttl_seconds)
        except RedisError as exc:
            raise SSHTicketStorageError(f"Failed to store SSH ticket in Redis: {exc}") from exc

        return ticket

    async def consume_ticket(
        self,
        *,
        ticket: str,
        expected_session_id: uuid.UUID,
        expected_user_id: uuid.UUID,
        expected_asset_id: Optional[uuid.UUID] = None,
    ) -> SSHTicketData:
        """
        Atomically retrieve and delete the ticket using Redis GETDEL.
        Validates binding against expected_session_id, expected_user_id,
        and optionally expected_asset_id.
        Rejects missing, expired, reused, or mismatched tickets.
        """
        if not ticket or not isinstance(ticket, str):
            raise SSHTicketInvalidError("Invalid ticket token provided.")

        key = self._ticket_key(ticket)

        try:
            r = await self._get_redis()
            raw_data = await r.getdel(key)
        except RedisError as exc:
            raise SSHTicketStorageError(f"Failed to access Redis to consume ticket: {exc}") from exc

        if raw_data is None:
            raise SSHTicketInvalidError("Ticket not found, expired, or already consumed.")

        try:
            data = json.loads(raw_data)
            ticket_session_id = uuid.UUID(data["session_id"])
            ticket_user_id = uuid.UUID(data["user_id"])
            ticket_asset_id = uuid.UUID(data["asset_id"])
            ticket_request_id = uuid.UUID(data["access_request_id"])
            ticket_grant_id = uuid.UUID(data["jit_grant_id"])
            created_at = data["created_at"]
        except (KeyError, ValueError, TypeError) as exc:
            raise SSHTicketInvalidError(f"Malformed ticket payload: {exc}") from exc

        if ticket_session_id != expected_session_id:
            raise SSHTicketInvalidError(
                f"Ticket session mismatch (expected {expected_session_id}, got {ticket_session_id})."
            )

        if ticket_user_id != expected_user_id:
            raise SSHTicketInvalidError(
                f"Ticket user mismatch (expected {expected_user_id}, got {ticket_user_id})."
            )

        if expected_asset_id is not None and ticket_asset_id != expected_asset_id:
            raise SSHTicketInvalidError(
                f"Ticket asset mismatch (expected {expected_asset_id}, got {ticket_asset_id})."
            )

        return SSHTicketData(
            ticket=ticket,
            session_id=ticket_session_id,
            user_id=ticket_user_id,
            asset_id=ticket_asset_id,
            access_request_id=ticket_request_id,
            jit_grant_id=ticket_grant_id,
            created_at=created_at,
        )


_default_ticket_service: Optional[SSHTicketService] = None


def get_ssh_ticket_service() -> SSHTicketService:
    """FastAPI dependency for shared SSHTicketService."""
    global _default_ticket_service
    if _default_ticket_service is None:
        _default_ticket_service = SSHTicketService()
    return _default_ticket_service
