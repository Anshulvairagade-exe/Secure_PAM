"""
SSH Gateway seam — where a checked-out credential is handed to the
SSH protocol gateway and never to the client.

`PendingSSHGateway` is the placeholder until the real SSH transport/daemon
integration exists: it confirms it received a live, non-wiped credential inside
the CredentialService checkout block and returns only non-secret connection
details.

To strictly uphold PAM integrity:
- `is_connected` is False for the placeholder gateway, ensuring the control plane
  never falsely reports an unestablished session as ACTIVE.
- The credential must never appear in what `prepare()` returns.
"""

from dataclasses import dataclass
from typing import Optional, Protocol

from app.models.asset import Asset
from app.models.session import Session
from app.secret_providers import Credential


@dataclass(frozen=True)
class SSHGatewayConnection:
    """Safe to return to the client — no credential fields by design."""

    protocol: str
    hostname: str
    port: int
    gateway_session_id: Optional[str] = None
    is_connected: bool = False


class SSHGateway(Protocol):
    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> SSHGatewayConnection: ...


class SSHError(Exception):
    """The gateway could not prepare or connect the session. `code` is a
    stable, non-secret reason (see app/services/credential_errors.py)."""

    def __init__(self, message: str = "SSH gateway error", code: str = "GATEWAY_ERROR"):
        super().__init__(message)
        self.code = code


class PendingSSHGateway:
    """
    Placeholder SSH Gateway for Phase 10.1 backend foundation.

    Confirms that a live credential was checked out inside the CredentialService
    checkout context block, verifies non-wiped state, and produces safe connection
    descriptors for the client.
    Because live upstream SSH transport is not yet active, is_connected is False,
    ensuring the control plane never falsely marks the session as ACTIVE or the
    recording as RECORDING.
    """

    async def prepare(self, *, session: Session, asset: Asset, credential: Credential) -> SSHGatewayConnection:
        if credential.is_wiped:
            raise SSHError("Credential was not live when the SSH gateway received it")
        return SSHGatewayConnection(
            protocol="ssh",
            hostname=asset.hostname,
            port=asset.port,
            gateway_session_id=None,
            is_connected=False,
        )


def get_ssh_gateway() -> SSHGateway:
    return PendingSSHGateway()
