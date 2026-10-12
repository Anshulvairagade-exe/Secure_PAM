"""
OpenBao KV v2 provider.

The lab server speaks the Vault HTTP API. A stored reference such as
`secret/targets/LINUX-DEV-01` is read at `/v1/secret/data/targets/LINUX-DEV-01`.
The runtime token is the least-privilege `securepam-runtime` token, never
the dev root token.
"""

import re
from pathlib import Path
from typing import Optional

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.secrets.base import (
    SecretDeniedError,
    SecretMaterial,
    SecretNotFoundError,
    SecretProvider,
    SecretTimeoutError,
    SecretUnauthenticatedError,
    SecretUnavailableError,
)

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ALLOWED_PREFIXES = ("targets", "applications")


def normalize_logical_path(vault_path: str, mount: str) -> str:
    """Map a stored reference to the KV v2 logical path, or reject it."""
    raw = vault_path.strip()
    if not raw or "\\" in raw or "\x00" in raw or "://" in raw:
        raise SecretDeniedError("Invalid secret path")

    parts = [part for part in raw.split("/") if part]
    mount_name = mount.strip("/")
    if parts and parts[0] == mount_name:
        parts = parts[1:]
    if parts and parts[0] == "data":
        parts = parts[1:]

    if len(parts) < 2 or parts[0] not in _ALLOWED_PREFIXES:
        raise SecretDeniedError("Invalid secret path")
    if any(_SEGMENT.fullmatch(part) is None for part in parts):
        raise SecretDeniedError("Invalid secret path")
    return "/".join(parts)


class DisabledSecretProvider:
    """Used when OpenBao is off or no runtime token is configured."""

    async def read(self, vault_path: str) -> SecretMaterial:
        raise SecretUnavailableError("OpenBao retrieval is disabled")


class OpenBaoSecretProvider:
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        mount: str = "secret",
        client: Optional[httpx.AsyncClient] = None,
        logger=None,
        timeout_seconds: float = 5.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._client = client
        self._logger = logger if logger is not None else get_logger("securepam.secrets")
        self._timeout = timeout_seconds

    async def read(self, vault_path: str) -> SecretMaterial:
        logical = normalize_logical_path(vault_path, self._mount)
        if not self._token:
            self._log("warning", "secret_read_failed", path=logical, error_code="unauthenticated")
            raise SecretUnauthenticatedError("OpenBao authentication failed")

        if self._client is not None:
            return await self._read_with(self._client, logical)

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._read_with(client, logical)

    async def _read_with(self, client: httpx.AsyncClient, logical: str) -> SecretMaterial:
        url = f"{self._base_url}/v1/{self._mount}/data/{logical}"
        try:
            response = await client.get(url, headers={"X-Vault-Token": self._token})
        except httpx.TimeoutException:
            self._log("warning", "secret_read_failed", path=logical, error_code="timeout")
            raise SecretTimeoutError("OpenBao request timed out") from None
        except httpx.HTTPError:
            self._log("warning", "secret_read_failed", path=logical, error_code="unavailable")
            raise SecretUnavailableError("OpenBao is unavailable") from None

        if response.status_code == 401:
            self._log("warning", "secret_read_failed", path=logical, error_code="unauthenticated")
            raise SecretUnauthenticatedError("OpenBao authentication failed")
        if response.status_code == 403:
            self._log("warning", "secret_read_failed", path=logical, error_code="denied")
            raise SecretDeniedError("OpenBao denied access to the secret")
        if response.status_code == 404:
            self._log("warning", "secret_read_failed", path=logical, error_code="not_found")
            raise SecretNotFoundError("Secret was not found")
        if response.status_code != 200:
            self._log(
                "warning",
                "secret_read_failed",
                path=logical,
                error_code="unavailable",
                status_code=response.status_code,
            )
            raise SecretUnavailableError("OpenBao is unavailable")

        material = _material_from_kv2(response)
        self._log("info", "secret_read", path=logical)
        return material

    def _log(self, level: str, event: str, **kwargs: object) -> None:
        getattr(self._logger, level)(event, **kwargs)


def _material_from_kv2(response: httpx.Response) -> SecretMaterial:
    try:
        payload = response.json()
        data = payload["data"]["data"]
    except (KeyError, TypeError, ValueError):
        raise SecretUnavailableError("OpenBao returned an unreadable response") from None
    if not isinstance(data, dict):
        raise SecretUnavailableError("OpenBao returned an unreadable response")

    def optional_text(key: str) -> Optional[str]:
        value = data.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise SecretUnavailableError("OpenBao returned an unreadable response")
        return value

    return SecretMaterial(
        username=optional_text("username"),
        password=optional_text("password"),
        private_key=optional_text("private_key"),
    )


def runtime_vault_token() -> str:
    """Return the least-privilege token. Never log the result."""
    configured = settings.VAULT_TOKEN.strip()
    if configured:
        return configured
    path = settings.VAULT_TOKEN_FILE.strip()
    if not path:
        return ""
    try:
        file = Path(path)
        if not file.is_file():
            return ""
        return file.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def openbao_retrieval_enabled() -> bool:
    """True when a runtime token is available from the env or the lab token file."""
    if not runtime_vault_token():
        return False
    return settings.VAULT_ENABLED or bool(settings.VAULT_TOKEN_FILE.strip())


def get_secret_provider() -> SecretProvider:
    """Application provider. Disabled until a non-empty runtime token is configured."""
    token = runtime_vault_token()
    if not openbao_retrieval_enabled():
        return DisabledSecretProvider()
    return OpenBaoSecretProvider(
        base_url=settings.VAULT_URL,
        token=token,
        mount=settings.VAULT_MOUNT_PATH,
    )
