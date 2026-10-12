"""
RDP gateway seam — where a checked-out credential is handed to the
protocol gateway (Guacamole) and never to the client.

`PendingGuacamoleGateway` is the placeholder until the real Guacamole
integration exists: it confirms it received a live credential inside the
CredentialService checkout block and returns only non-secret connection
details. The real implementation must inject the credential server-side
(e.g. an encrypted guacamole-lite token or a Guacamole connection created
via its API) — the credential must never appear in what `prepare()`
returns, because that is sent to the browser.
"""

from dataclasses import dataclass
from typing import Optional, Protocol

from app.models.asset import Asset
from app.models.session import Session
from app.secret_providers import Credential


@dataclass(frozen=True)
class GatewayConnection:
    """Safe to return to the client — no credential fields by design."""

    protocol: str
    hostname: str
    port: int
    gateway_session_id: Optional[str] = None


class RDPGateway(Protocol):
    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> GatewayConnection: ...


class GatewayError(Exception):
    """The gateway could not prepare the connection."""


class PendingGuacamoleGateway:
    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> GatewayConnection:
        if credential.is_wiped:
            raise GatewayError("Credential was not live when the gateway received it")
        return GatewayConnection(protocol="rdp", hostname=asset.hostname, port=asset.port)


def get_rdp_gateway() -> RDPGateway:
    return PendingGuacamoleGateway()
