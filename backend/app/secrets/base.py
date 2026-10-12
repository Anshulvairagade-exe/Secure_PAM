"""
Secret retrieval boundary.

A vault path stored in PostgreSQL is not authorization to read the secret.
Callers must already have passed SecurePAM's own authorization and JIT
checks before they call a SecretProvider.

Exception text, repr, and logs must never contain secret values, private
keys, or OpenBao tokens.
"""

from dataclasses import dataclass
from typing import Optional, Protocol


class SecretError(Exception):
    """Base error for secret retrieval. `code` is safe to log and return."""

    code = "secret_error"


class SecretDeniedError(SecretError):
    code = "denied"


class SecretNotFoundError(SecretError):
    code = "not_found"


class SecretUnauthenticatedError(SecretError):
    code = "unauthenticated"


class SecretTimeoutError(SecretError):
    code = "timeout"


class SecretUnavailableError(SecretError):
    code = "unavailable"


@dataclass(frozen=True)
class SecretMaterial:
    """Secret bytes returned to a gateway. Never log or serialize this."""

    username: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None

    def __repr__(self) -> str:
        fields = [
            name
            for name, value in (
                ("username", self.username),
                ("password", self.password),
                ("private_key", self.private_key),
            )
            if value is not None
        ]
        return f"SecretMaterial(fields={fields})"


class SecretProvider(Protocol):
    """Reads one secret by its vault reference. Implementations must not log values."""

    async def read(self, vault_path: str) -> SecretMaterial:
        ...
