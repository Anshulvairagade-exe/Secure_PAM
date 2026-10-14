"""
RDP gateway: Apache Guacamole's guacd.

`GuacdRdpGateway` is the real integration. Launch (REST) only *prepares*: it
checks guacd is reachable and that the credential can be checked out. The
connection itself is made when the operator's browser redeems its one-time
ticket on the RDP WebSocket (app/api/v1/rdp_sessions.py), which opens a TCP
connection to guacd, hands it the target and the credential, and relays the
Guacamole instruction stream. That keeps the credential on the server for its
whole life and lets termination close a connection this process really owns.

`PendingGuacamoleGateway` is what `get_rdp_gateway()` returns when no guacd is
configured (GUACD_HOST unset): it reports itself undeployed and launches are
refused honestly instead of pretending.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Protocol

from app.core.config import settings
from app.models.asset import Asset
from app.models.session import Session
from app.secret_providers import Credential
from app.services.guacamole import GuacamoleError, GuacdStream, connect_guacd

logger = logging.getLogger("securepam.rdp")

# guacd does not reliably close the socket after `disconnect`, so this is only a courtesy wait; the
# recording's finality is decided by file quiescence (see rdp_recording).
GRACEFUL_CLOSE_SECONDS = 4.0


@dataclass(frozen=True)
class GatewayConnection:
    """Safe to return to the client — no credential fields by design."""

    protocol: str
    hostname: str
    port: int
    gateway_session_id: Optional[str] = None
    # True only once a real RDP connection exists. Preparing a session never connects.
    is_connected: bool = False


class RDPGateway(Protocol):
    is_deployed: bool

    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> GatewayConnection: ...


class GatewayError(Exception):
    """The gateway could not prepare the connection."""


class PendingGuacamoleGateway:
    """No guacd configured."""

    is_deployed = False

    async def available(self) -> bool:
        return False

    def get_live_connection(self, session_id):
        return None

    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> GatewayConnection:
        raise GatewayError("No RDP gateway is deployed")


@dataclass
class LiveRDPConnection:
    session_id: object
    stream: GuacdStream
    guacd_connection_id: str = ""
    closed: bool = field(default=False)

    async def close(self, timeout: float = GRACEFUL_CLOSE_SECONDS) -> bool:
        """Ask guacd to disconnect (so it stops the RDP client and flushes its recording), and give it a
        moment to close the socket. Returns True if it did. This does not make the recording final; the
        finalizer waits for the file to go quiet. Callers must have stopped any reader of this stream."""
        self.closed = True
        finished = False
        try:
            self.stream.send("disconnect")
            await self.stream.writer.drain()
            loop = asyncio.get_event_loop()
            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                data = await asyncio.wait_for(self.stream.reader.read(65536), remaining)
                if not data:
                    finished = True
                    break
        except (OSError, asyncio.TimeoutError):
            pass
        await self.stream.close()
        return finished


class GuacdRdpGateway:
    is_deployed = True

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self._live: Dict[object, LiveRDPConnection] = {}

    # --- availability -----------------------------------------------------------------
    async def available(self) -> bool:
        try:
            stream = await connect_guacd(self.host, self.port, timeout=2.0)
        except GuacamoleError:
            return False
        await stream.close()
        return True

    # --- registry (same shape as the SSH gateway, so termination treats both alike) -------
    def get_live_connection(self, session_id) -> Optional[LiveRDPConnection]:
        return self._live.get(session_id)

    def register(self, conn: LiveRDPConnection) -> None:
        self._live[conn.session_id] = conn

    async def close_connection(self, session_id) -> None:
        conn = self._live.pop(session_id, None)
        if conn is not None:
            await conn.close()

    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> GatewayConnection:
        if credential.is_wiped:
            raise GatewayError("Credential was not live when the gateway received it")
        if not await self.available():
            raise GatewayError("guacd is not reachable")
        return GatewayConnection(protocol="rdp", hostname=asset.hostname, port=asset.port)


_gateway: Optional[RDPGateway] = None


def get_rdp_gateway() -> RDPGateway:
    global _gateway
    if _gateway is None:
        _gateway = GuacdRdpGateway(settings.GUACD_HOST, settings.GUACD_PORT) if settings.RDP_GATEWAY_ENABLED \
            else PendingGuacamoleGateway()
    return _gateway


def rdp_recording_root() -> Path:
    return Path(settings.RDP_RECORDING_PATH or f"{settings.RECORDING_STORAGE_PATH}/rdp").resolve()


def rdp_recording_writable() -> bool:
    import os
    root = rdp_recording_root()
    try:
        root.mkdir(mode=0o770, parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(root, os.W_OK | os.X_OK)
