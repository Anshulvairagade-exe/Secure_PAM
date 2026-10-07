"""
Identity provider factory.

app.core.deps calls get_token_validator() instead of hard-coding DevAuth —
this is the single switch point for moving from DEV_MODE local JWTs to
Keycloak/OIDC. Nothing else in the authorization layer needs to change.
"""

from app.auth.base import InvalidTokenError, TokenIdentity, TokenValidator
from app.auth.dev_provider import DevTokenValidator
from app.auth.oidc_provider import OIDCTokenValidator
from app.core.config import settings

__all__ = [
    "TokenIdentity",
    "TokenValidator",
    "InvalidTokenError",
    "get_token_validator",
]


def get_token_validator() -> TokenValidator:
    if settings.DEV_MODE:
        return DevTokenValidator()
    return OIDCTokenValidator()
