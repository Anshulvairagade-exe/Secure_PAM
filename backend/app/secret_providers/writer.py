"""
Credential WRITER for the integrated asset-credential workflow (admin-only).

A separate OpenBao identity (OPENBAO_WRITER_TOKEN, policy securepam-writer: create+update on the
registered paths, no read) so the backend's runtime reader never gains write access. Same hardening
as the reader (app.secret_providers.openbao): token only in the header, no redirects, no proxy env,
strict timeouts, every failure fails closed with a value-free message. The mock provider never
accepts real credentials: provisioning is "not configured" unless SECRET_PROVIDER=openbao.
"""

from typing import Optional
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from app.core.config import settings
from app.secret_providers.base import (
    SecretAccessDeniedError,
    SecretProviderError,
    SecretProviderUnavailableError,
)
from app.secret_providers.paths import validate_secret_path


class CredentialWriterNotConfigured(SecretProviderError):
    """Provisioning is disabled in this deployment (no writer identity / not OpenBao)."""


class OpenBaoCredentialWriter:
    def __init__(self, *, addr: str, token: SecretStr, mount_point: str, path_prefix: str,
                 connect_timeout: float, request_timeout: float, ca_cert: Optional[str] = None,
                 transport: Optional[httpx.AsyncBaseTransport] = None):
        self._addr, self._token, self._mount, self._prefix = addr.rstrip("/"), token, mount_point, path_prefix
        self._timeout = httpx.Timeout(request_timeout, connect=connect_timeout)
        self._verify = ca_cert or True
        self._transport = transport

    def __repr__(self) -> str:
        return f"<OpenBaoCredentialWriter addr={self._addr} mount={self._mount}>"

    async def write(self, path: str, data: dict) -> int:
        """Create/update one KV v2 secret; returns the new version. Never echoes the data."""
        validate_secret_path(path, self._prefix)
        headers = {"X-Vault-Token": self._token.get_secret_value(), "X-Vault-Request": "true"}
        try:
            async with httpx.AsyncClient(base_url=self._addr, timeout=self._timeout, verify=self._verify,
                                         transport=self._transport, follow_redirects=False,
                                         trust_env=False) as client:
                response = await client.post(f"/v1/{quote(self._mount)}/data/{quote(path)}",
                                             json={"data": data}, headers=headers)
        except httpx.TimeoutException:
            raise SecretProviderUnavailableError("OpenBao request timed out") from None
        except httpx.HTTPError:
            raise SecretProviderUnavailableError("OpenBao is unreachable (or its certificate is not trusted)") from None
        finally:
            del headers, data
        if response.status_code in (401, 403):
            raise SecretAccessDeniedError(f"OpenBao denied the write to {path} (HTTP {response.status_code})")
        if response.status_code == 429 or response.status_code >= 500:
            raise SecretProviderUnavailableError(f"OpenBao unavailable (HTTP {response.status_code})")
        if response.status_code not in (200, 204):
            raise SecretProviderError(f"Unexpected OpenBao response (HTTP {response.status_code})")
        try:
            version = ((response.json() or {}).get("data") or {}).get("version")
        except ValueError:
            version = None
        if not isinstance(version, int):
            raise SecretProviderError("OpenBao did not report the written version")
        return version


def writer_status() -> tuple[bool, str]:
    if settings.SECRET_PROVIDER != "openbao":
        return False, ("Credential provisioning needs the OpenBao secret provider; this deployment uses the "
                       "development stand-in, which must never hold real credentials.")
    if not settings.OPENBAO_WRITER_TOKEN.get_secret_value():
        return False, "No credential-writer identity is configured (OPENBAO_WRITER_TOKEN)."
    return True, "OpenBao credential writer configured."


def get_credential_writer() -> OpenBaoCredentialWriter:
    ok, reason = writer_status()
    if not ok:
        raise CredentialWriterNotConfigured(reason)
    return OpenBaoCredentialWriter(
        addr=settings.OPENBAO_ADDR, token=settings.OPENBAO_WRITER_TOKEN, mount_point=settings.OPENBAO_MOUNT_POINT,
        path_prefix=settings.OPENBAO_SECRET_PATH_PREFIX, connect_timeout=settings.OPENBAO_CONNECT_TIMEOUT_SECONDS,
        request_timeout=settings.OPENBAO_REQUEST_TIMEOUT_SECONDS, ca_cert=settings.OPENBAO_CA_CERT or None,
    )
