"""
SecretProvider interface, the Credential value type, and the exception
hierarchy every provider maps its failures onto.

The interface is deliberately read-only: SecurePAM retrieves credentials,
it never writes, rotates or deletes them (rotation, if added later, belongs
to a separate, separately-authorized component). A provider that cannot be
reached, or answers with anything unexpected, raises — callers fail closed.

Exception messages and reprs here are safe to log and audit: they carry at
most a status code and the (non-secret) reference path, never a token,
response body or secret value.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


# --- Exceptions ---

class SecretProviderError(Exception):
    """Base class. `code` is a stable machine-readable reason for audit rows."""

    code = "PROVIDER_ERROR"


class SecretProviderConfigError(SecretProviderError):
    code = "PROVIDER_MISCONFIGURED"


class InvalidSecretReferenceError(SecretProviderError):
    code = "INVALID_SECRET_REFERENCE"


class SecretNotFoundError(SecretProviderError):
    code = "SECRET_NOT_FOUND"


class SecretAccessDeniedError(SecretProviderError):
    """The provider refused the read (e.g. OpenBao 403)."""

    code = "PROVIDER_ACCESS_DENIED"


class SecretProviderUnavailableError(SecretProviderError):
    """Connection failure, timeout, sealed/standby node, or 5xx."""

    code = "PROVIDER_UNAVAILABLE"


class MalformedSecretError(SecretProviderError):
    """Reachable, but the response/secret shape isn't what we require."""

    code = "MALFORMED_SECRET"


# --- Values ---

class Credential:
    """
    A retrieved username/secret pair, kept as short-lived as practical.

    - repr/str never show the secret (so an accidental log line or a
      traceback's local-variable dump can't leak it);
    - `wipe()` drops the reference, after which `reveal()` raises —
      CredentialService's checkout context manager calls it on exit.

    Python cannot zero an immutable str in place, so wipe() removes this
    object's reference rather than scrubbing memory; the gateway that
    consumes the secret should likewise hold it only for the handshake.
    """

    __slots__ = ("username", "secret_type", "version", "_secret")

    def __init__(self, *, username: Optional[str], secret: str, secret_type: str, version: Optional[int]):
        self.username = username
        self.secret_type = secret_type
        self.version = version
        self._secret: Optional[str] = secret

    def reveal(self) -> str:
        if self._secret is None:
            raise RuntimeError("Credential has been wiped")
        return self._secret

    def wipe(self) -> None:
        self._secret = None

    @property
    def is_wiped(self) -> bool:
        return self._secret is None

    def __repr__(self) -> str:
        return f"<Credential username={self.username!r} type={self.secret_type} version={self.version} secret=***>"

    __str__ = __repr__

    def __reduce__(self):  # refuse pickling (e.g. into a cache or task queue)
        raise TypeError("Credential objects cannot be serialized")


@dataclass(frozen=True)
class SecretRecord:
    """Raw KV payload + version as read from the provider. Internal only —
    CredentialService turns it into a Credential immediately."""

    data: dict
    version: Optional[int]

    def __repr__(self) -> str:
        return f"<SecretRecord keys={sorted(self.data)} version={self.version}>"


@dataclass(frozen=True)
class ProviderHealth:
    provider: str
    healthy: bool
    detail: str  # safe to expose on /health/detailed — no token, no secret
    latency_ms: Optional[float] = None


# --- Interface ---

class SecretProvider(ABC):
    name: str

    @abstractmethod
    async def read_secret(self, path: str, *, version: Optional[int] = None) -> SecretRecord:
        """Read the KV secret at `path` (relative to the provider's mount,
        already validated by the caller). Raises a SecretProviderError
        subclass on any failure — never returns partial data."""

    @abstractmethod
    async def health(self) -> ProviderHealth:
        """Reachability check. Must never raise and never include a token
        or secret value in the result."""
