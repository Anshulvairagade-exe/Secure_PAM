"""
OpenBao (Vault-API-compatible) KV v2 provider.

Talks to the KV v2 HTTP API directly with httpx (already a pinned
dependency) rather than hvac: hvac is synchronous (requests-based) and
would block the event loop, and SecurePAM needs exactly two endpoints —
`GET /v1/<mount>/data/<path>` and `GET /v1/sys/health`.

Hardening choices:
- The token goes only in the X-Vault-Token header, held as a SecretStr
  until the moment the request is built; it is never part of a URL,
  exception, log line or health result.
- trust_env=False: no proxy / .netrc / SSL_CERT env picked up implicitly.
- follow_redirects=False: a redirect can't bounce the token elsewhere.
- Separate connect and request timeouts; every transport error maps to
  SecretProviderUnavailableError so callers fail closed.
- Exceptions are raised `from None` so the httpx cause (which can carry
  the response) is not chained into tracebacks.
"""

import time
from typing import Optional
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from app.secret_providers.base import (
    MalformedSecretError,
    ProviderHealth,
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretProvider,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretRecord,
)
from app.secret_providers.paths import validate_secret_path


class OpenBaoSecretProvider(SecretProvider):
    name = "openbao"

    def __init__(
        self,
        *,
        addr: str,
        token: SecretStr,
        mount_point: str,
        path_prefix: str,
        connect_timeout: float,
        request_timeout: float,
        ca_cert: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,  # tests inject httpx.MockTransport
    ):
        self._addr = addr.rstrip("/")
        self._token = token
        self._mount = mount_point
        self._prefix = path_prefix
        self._timeout = httpx.Timeout(request_timeout, connect=connect_timeout)
        self._verify = ca_cert or True
        self._transport = transport

    def __repr__(self) -> str:
        return f"<OpenBaoSecretProvider addr={self._addr} mount={self._mount}>"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._addr,
            timeout=self._timeout,
            verify=self._verify,
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
        )

    async def read_secret(self, path: str, *, version: Optional[int] = None) -> SecretRecord:
        validate_secret_path(path, self._prefix)
        url = f"/v1/{quote(self._mount)}/data/{quote(path)}"
        params = {"version": str(version)} if version is not None else None
        headers = {"X-Vault-Token": self._token.get_secret_value(), "X-Vault-Request": "true"}

        try:
            async with self._client() as client:
                response = await client.get(url, params=params, headers=headers)
        except httpx.TimeoutException:
            raise SecretProviderUnavailableError("OpenBao request timed out") from None
        except httpx.HTTPError:
            raise SecretProviderUnavailableError("OpenBao is unreachable") from None
        finally:
            del headers

        status = response.status_code
        if status == 200:
            return self._parse_kv2(response, path)
        if status == 404:
            raise SecretNotFoundError(f"No secret at reference {path}")
        if status in (401, 403):
            raise SecretAccessDeniedError(f"OpenBao denied read of reference {path} (HTTP {status})")
        if status == 429 or status >= 500:
            raise SecretProviderUnavailableError(f"OpenBao unavailable (HTTP {status})")
        raise SecretProviderError(f"Unexpected OpenBao response (HTTP {status})")

    @staticmethod
    def _parse_kv2(response: httpx.Response, path: str) -> SecretRecord:
        try:
            body = response.json()
        except ValueError:
            raise MalformedSecretError("OpenBao returned a non-JSON response") from None

        envelope = body.get("data") if isinstance(body, dict) else None
        if not isinstance(envelope, dict):
            raise MalformedSecretError("OpenBao response has no KV v2 data envelope")
        data = envelope.get("data")
        metadata = envelope.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise MalformedSecretError("OpenBao response metadata is malformed")

        # A soft-deleted or destroyed version comes back with data=null.
        if metadata.get("destroyed") or metadata.get("deletion_time") or data is None:
            raise SecretNotFoundError(f"Secret at reference {path} is deleted or destroyed")
        if not isinstance(data, dict):
            raise MalformedSecretError("OpenBao KV v2 data is not an object")

        version = metadata.get("version")
        return SecretRecord(data=data, version=version if isinstance(version, int) else None)

    async def health(self) -> ProviderHealth:
        # sys/health is unauthenticated — no token is sent for this check.
        start = time.monotonic()
        try:
            async with self._client() as client:
                response = await client.get("/v1/sys/health")
        except httpx.HTTPError:
            return ProviderHealth(self.name, False, "OpenBao unreachable")
        latency = round((time.monotonic() - start) * 1000, 2)

        if response.status_code == 200:
            return ProviderHealth(self.name, True, "OpenBao reachable, unsealed, active", latency)
        detail = {
            429: "OpenBao node is a standby",
            501: "OpenBao is not initialized",
            503: "OpenBao is sealed",
        }.get(response.status_code, f"OpenBao health returned HTTP {response.status_code}")
        return ProviderHealth(self.name, False, detail, latency)
