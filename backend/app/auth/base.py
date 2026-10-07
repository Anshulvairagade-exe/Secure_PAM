"""
Identity provider abstraction.

SecurePAM separates two concerns that must never be merged:

  1. AUTHENTICATION / IDENTITY — "who is this?"
     Provided today by DevTokenValidator (DEV_MODE local JWTs) and, later,
     by OIDCTokenValidator (Keycloak). This layer answers only "who is this
     person" and hands back claims from the token. Nothing more.

  2. AUTHORIZATION — "what can they do?"
     Always decided by SecurePAM's own RBAC tables (roles, permissions,
     user_roles) via app.core.deps.PermissionChecker / RoleChecker, looked
     up against the LOCAL User row after identity has been resolved.

A TokenValidator implementation must never be trusted for role/permission
decisions — `TokenIdentity.token_roles` is informational only (useful for
auditing "what did the IdP claim"), and is NOT consulted by any
authorization check in this codebase. When Keycloak/OIDC replaces DevAuth,
only a new TokenValidator needs to be written; app.core.deps and every
permission-gated route stay unchanged.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Protocol


@dataclass(frozen=True)
class TokenIdentity:
    """Claims extracted from a validated token, not yet resolved to a local User."""

    subject: str
    email: Optional[str] = None
    name: Optional[str] = None
    # Roles claimed BY THE TOKEN/IdP. Informational only — never used for
    # authorization decisions. SecurePAM's local RBAC is the sole source of
    # truth for what a user can do.
    token_roles: List[str] = field(default_factory=list)


class InvalidTokenError(Exception):
    """Raised by a TokenValidator when a token is missing, malformed, or expired."""


class TokenValidator(Protocol):
    """Strategy interface for validating a bearer token into a TokenIdentity."""

    def validate(self, token: str) -> TokenIdentity:
        ...
