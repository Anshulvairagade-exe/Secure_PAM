"""
DevTokenValidator — validates local HS256 JWTs issued by /auth/login.

Only used when DEV_MODE=true. Production/lab deployments use
OIDCTokenValidator (Keycloak) instead — see app/auth/oidc_provider.py.
"""

from jose import JWTError

from app.auth.base import InvalidTokenError, TokenIdentity, TokenValidator
from app.core.security import decode_dev_token


class DevTokenValidator(TokenValidator):
    def validate(self, token: str) -> TokenIdentity:
        try:
            payload = decode_dev_token(token)
        except JWTError as e:
            raise InvalidTokenError(str(e)) from e

        subject = payload.get("sub")
        if not subject:
            raise InvalidTokenError("Token missing subject claim")

        return TokenIdentity(
            subject=subject,
            email=payload.get("email"),
            name=payload.get("name"),
            token_roles=payload.get("realm_access", {}).get("roles", []),
        )
