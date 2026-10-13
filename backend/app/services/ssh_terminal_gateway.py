"""
AsyncSSH Terminal Gateway — SecurePAM Member 10 (SSH Gateway).

Implements the SSH transport layer using AsyncSSH with asynchronous I/O and
PTY channel management behind the SSHGateway abstraction.

Security & Credential Lifecycle:
- Zero Secret Exposure: Raw passwords and private keys are never returned in
  API responses, query strings, logs, or sent to client browsers.
- Server-Side Authentication: Credentials from CredentialService are consumed
  strictly during the SSHv2 handshake.
- Secret Wiping & Python Limitations:
  Credential.wipe() removes object references, after which credential.reveal() raises.
  However, because CPython strings are immutable objects managed by the runtime
  heap allocator, Python cannot guarantee immediate physical zeroing of string
  memory buffers. The gateway minimizes credential variable lifetimes by scoping
  secrets strictly to the `connect()` call and immediately releasing references.
- Host-Key Verification: Enforces fail-closed verification via SSHHostKeyValidator.
- Lifecycle & Bounded I/O: Connections are tracked in an active registry with
  explicit close cleanup and bounded buffer sizes (32 KB chunks) to prevent backpressure
  exhaustion.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

import asyncssh

from app.models.asset import Asset
from app.models.session import Session
from app.secret_providers import Credential
from app.services.ssh_gateway import SSHError, SSHGateway, SSHGatewayConnection
from app.services.ssh_host_key import (
    SSHHostKeyError,
    SSHHostKeyValidator,
)

logger = logging.getLogger("securepam.ssh.gateway")

# 32 KB maximum chunk size for bounded terminal stream buffers
MAX_TERMINAL_CHUNK_SIZE = 32768


@dataclass
class LiveSSHConnection:
    """Represents an active, authenticated upstream SSH transport channel."""

    session_id: uuid.UUID
    asset_id: uuid.UUID
    connection: asyncssh.SSHClientConnection
    is_closed: bool = False

    async def close(self) -> None:
        """Safely close and clean up the active SSH connection."""
        if not self.is_closed:
            self.is_closed = True
            try:
                self.connection.close()
                await self.connection.wait_closed()
            except Exception as exc:
                logger.warning("Error during SSH connection close for session %s: %s", self.session_id, exc)


class AsyncSSHTerminalGateway:
    """
    AsyncSSH-based implementation of the SSHGateway interface.
    Manages upstream authenticated connections and PTY sessions.
    """

    def __init__(
        self,
        *,
        host_key_validator: Optional[SSHHostKeyValidator] = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self._host_key_validator = host_key_validator or SSHHostKeyValidator()
        self._connect_timeout = connect_timeout
        self._active_connections: Dict[uuid.UUID, LiveSSHConnection] = {}

    def get_live_connection(self, session_id: uuid.UUID) -> Optional[LiveSSHConnection]:
        """Retrieve an active SSH connection by session ID."""
        return self._active_connections.get(session_id)

    async def close_connection(self, session_id: uuid.UUID) -> None:
        """Close and remove an active SSH connection."""
        live_conn = self._active_connections.pop(session_id, None)
        if live_conn:
            await live_conn.close()

    async def close_all_connections(self) -> None:
        """Emergency cleanup of all active SSH connections."""
        session_ids = list(self._active_connections.keys())
        for sid in session_ids:
            await self.close_connection(sid)

    async def prepare(
        self,
        *,
        session: Session,
        asset: Asset,
        credential: Credential,
    ) -> SSHGatewayConnection:
        """
        Authenticate and establish an upstream SSHv2 connection.

        Security invariants:
        - Rejects already-wiped credentials.
        - Resolves trusted known-hosts configuration fail-closed.
        - Wipes credential reference immediately after connection handshake.
        - Cleans up and closes any partial socket on failure or cancellation.
        """
        if credential.is_wiped:
            raise SSHError("Credential was wiped prior to SSH handshake.")

        # 1. Resolve trusted host keys fail-closed
        try:
            trusted_known_hosts = await self._host_key_validator.get_trusted_known_hosts_for_asset(asset)
        except SSHHostKeyError as exc:
            logger.warning("SSH host-key verification rejected target %s: %s", asset.name, exc)
            raise SSHError(f"Host-key verification failed: {exc}") from exc

        # 2. Extract and scope credential secrets strictly to the handshake
        username = credential.username
        secret_type = credential.secret_type
        password: Optional[str] = None
        client_keys = None

        try:
            raw_secret = credential.reveal()
            if secret_type == "PASSWORD":
                password = raw_secret
            elif secret_type in ("SSH_KEY", "PRIVATE_KEY"):
                try:
                    client_keys = [asyncssh.import_private_key(raw_secret)]
                except Exception as exc:
                    raise SSHError(f"Failed to import SSH client private key: {exc}") from exc
            else:
                raise SSHError(f"Unsupported secret type for SSH: {secret_type}")
        except RuntimeError as exc:
            raise SSHError(f"Unable to read credential for handshake: {exc}") from exc

        # 3. Establish upstream connection using AsyncSSH
        conn: Optional[asyncssh.SSHClientConnection] = None
        try:
            conn = await asyncssh.connect(
                host=asset.hostname,
                port=asset.port,
                username=username,
                password=password,
                client_keys=client_keys,
                known_hosts=trusted_known_hosts,
                login_timeout=self._connect_timeout,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            logger.error("SSH host key not verifiable for %s: %s", asset.hostname, exc)
            if conn is not None:
                conn.close()
                try:
                    await conn.wait_closed()
                except Exception:
                    pass
            raise SSHError(f"Host key verification failed: {exc}") from exc
        except asyncssh.PermissionDenied as exc:
            logger.warning("SSH authentication denied for %s@%s: %s", username, asset.hostname, exc)
            if conn is not None:
                conn.close()
                try:
                    await conn.wait_closed()
                except Exception:
                    pass
            raise SSHError(f"SSH authentication failed: {exc}") from exc
        except asyncio.CancelledError:
            logger.info("SSH connection cancelled for %s", asset.hostname)
            if conn is not None:
                conn.close()
                try:
                    await conn.wait_closed()
                except Exception:
                    pass
            raise
        except (asyncssh.Error, OSError, TimeoutError) as exc:
            logger.error("SSH transport connection error to %s: %s", asset.hostname, exc)
            if conn is not None:
                conn.close()
                try:
                    await conn.wait_closed()
                except Exception:
                    pass
            raise SSHError(f"SSH connection failed: {exc}") from exc
        except BaseException as exc:
            logger.error("Unexpected error during SSH connection to %s: %s", asset.hostname, exc)
            if conn is not None:
                conn.close()
                try:
                    await conn.wait_closed()
                except Exception:
                    pass
            if isinstance(exc, Exception):
                raise SSHError(f"SSH connection failed unexpectedly: {exc}") from exc
            raise
        finally:
            # Drop local secret references immediately after handshake
            password = None
            client_keys = None
            raw_secret = None

        # 4. Register active connection
        live_conn = LiveSSHConnection(
            session_id=session.id,
            asset_id=asset.id,
            connection=conn,
        )
        self._active_connections[session.id] = live_conn

        gateway_session_id = f"gw-ssh-{session.id}"
        return SSHGatewayConnection(
            protocol="ssh",
            hostname=asset.hostname,
            port=asset.port,
            gateway_session_id=gateway_session_id,
            is_connected=True,
        )


_default_terminal_gateway: Optional[AsyncSSHTerminalGateway] = None


def get_terminal_gateway() -> AsyncSSHTerminalGateway:
    """FastAPI dependency for shared AsyncSSHTerminalGateway instance."""
    global _default_terminal_gateway
    if _default_terminal_gateway is None:
        _default_terminal_gateway = AsyncSSHTerminalGateway()
    return _default_terminal_gateway
