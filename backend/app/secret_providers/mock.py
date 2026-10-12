"""
In-memory provider for development and tests. FAKE credentials only.

Only selected by an explicit SECRET_PROVIDER=mock (the default outside
production; Settings refuses it when ENVIRONMENT=production). It is never
used as a fallback for an unreachable or misconfigured OpenBao.
"""

from typing import Dict, Iterable, Optional

from app.secret_providers.base import (
    ProviderHealth,
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretProvider,
    SecretProviderUnavailableError,
    SecretRecord,
)
from app.secret_providers.paths import validate_secret_path

# Mirrors the local OpenBao test secret's path, with obviously fake values.
DEFAULT_MOCK_SECRETS: Dict[str, Dict[str, str]] = {
    "securepam/assets/test-linux-01": {"username": "mock-user", "password": "mock-password-not-real"},
}


class MockSecretProvider(SecretProvider):
    name = "mock"

    def __init__(
        self,
        secrets: Optional[Dict[str, Dict[str, str]]] = None,
        *,
        path_prefix: str = "securepam",
        available: bool = True,
        denied_paths: Iterable[str] = (),
    ):
        self._prefix = path_prefix
        self._secrets = {k: dict(v) for k, v in (DEFAULT_MOCK_SECRETS if secrets is None else secrets).items()}
        self.available = available
        self.denied_paths = set(denied_paths)
        self.reads: list[str] = []  # paths read, for test assertions — never values

    def __repr__(self) -> str:
        return f"<MockSecretProvider paths={len(self._secrets)}>"

    async def read_secret(self, path: str, *, version: Optional[int] = None) -> SecretRecord:
        validate_secret_path(path, self._prefix)
        self.reads.append(path)
        if not self.available:
            raise SecretProviderUnavailableError("Mock provider is unavailable")
        if path in self.denied_paths:
            raise SecretAccessDeniedError(f"Mock provider denied read of reference {path}")
        if path not in self._secrets:
            raise SecretNotFoundError(f"No secret at reference {path}")
        return SecretRecord(data=dict(self._secrets[path]), version=version or 1)

    async def health(self) -> ProviderHealth:
        if not self.available:
            return ProviderHealth(self.name, False, "Mock provider is unavailable")
        return ProviderHealth(self.name, True, "Mock provider active (fake credentials only)")
