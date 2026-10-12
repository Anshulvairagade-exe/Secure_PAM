
"""
OIDCTokenValidator — validates Keycloak-issued OIDC access tokens.

Authentication only: SecurePAM's local database remains the source of truth
for authorization and role/permission decisions.
"""

import threading
import time
from typing import Any

import httpx
from jose import JWTError, jwt

from app.auth.base import InvalidTokenError, TokenIdentity, TokenValidator
from app.core.config import settings


class OIDCProviderUnavailableError(Exception):
    """Keycloak's signing keys could not be retrieved."""


class OIDCTokenValidator(TokenValidator):
    """Validate RS256-signed Keycloak access tokens using cached JWKS."""

    _cache_lock = threading.Lock()
    _jwks_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
    _cache_ttl_seconds = 300
    _request_timeout_seconds = 5.0

    def _get_jwks(self) -> list[dict[str, Any]]:
        """Return cached signing keys, refreshing them when the cache expires."""
        url = settings.KEYCLOAK_JWKS_URL
        now = time.monotonic()

        with self._cache_lock:
            cached = self._jwks_cache.get(url)
            if cached and now < cached[0]:
                return cached[1]

            try:
                response = httpx.get(
                    url,
                    timeout=self._request_timeout_seconds,
                )
                response.raise_for_status()
                document = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OIDCProviderUnavailableError(
                    "Could not retrieve Keycloak signing keys"
                ) from exc

            keys = document.get("keys") if isinstance(document, dict) else None
            if not isinstance(keys, list):
                raise OIDCProviderUnavailableError(
                    "Keycloak returned an invalid JWKS document"
                )

            self._jwks_cache[url] = (
                time.monotonic() + self._cache_ttl_seconds,
                keys,
            )
            return keys

    def validate(self, token: str) -> TokenIdentity:
        """Verify a bearer token and extract its identity claims."""
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise InvalidTokenError("Malformed JWT header") from exc

        # Never accept an algorithm selected by an untrusted token.
        if header.get("alg") != "RS256":
            raise InvalidTokenError("Unsupported JWT signing algorithm")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidTokenError("JWT is missing its key ID")

        jwks = self._get_jwks()
        signing_key = next(
            (
                key
                for key in jwks
                if isinstance(key, dict)
                and key.get("kid") == kid
                and key.get("kty") == "RSA"
                and key.get("use", "sig") == "sig"
                and key.get("alg", "RS256") == "RS256"
            ),
            None,
        )

        if signing_key is None:
            # Refresh once to handle Keycloak signing-key rotation.
            with self._cache_lock:
                self._jwks_cache.pop(settings.KEYCLOAK_JWKS_URL, None)

            jwks = self._get_jwks()
            signing_key = next(
                (
                    key
                    for key in jwks
                    if isinstance(key, dict)
                    and key.get("kid") == kid
                    and key.get("kty") == "RSA"
                    and key.get("use", "sig") == "sig"
                    and key.get("alg", "RS256") == "RS256"
                ),
                None,
            )

        if signing_key is None:
            raise InvalidTokenError("No trusted signing key matches this token")

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=settings.KEYCLOAK_CLIENT_ID,
                issuer=settings.KEYCLOAK_ISSUER_URL,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "require_sub": True,
                },
            )
        except JWTError as exc:
            raise InvalidTokenError("OIDC token validation failed") from exc

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise InvalidTokenError("Token is missing a valid subject")

        # Require exp explicitly; verification alone doesn't require every
        # JWT implementation to reject a token that omits this claim.
        if "exp" not in claims:
            raise InvalidTokenError("Token is missing its expiration claim")

        realm_access = claims.get("realm_access")
        roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
        if not isinstance(roles, list):
            roles = []

        return TokenIdentity(
            subject=subject,
            email=claims.get("email"),
            name=claims.get("name"),
            token_roles=[role for role in roles if isinstance(role, str)],
        )
