"""
OIDCTokenValidator — validates Keycloak-issued OIDC access tokens.

NOT YET IMPLEMENTED. Wiring this up (Phase: Keycloak integration) requires:
  - Fetching Keycloak's JWKS (settings.KEYCLOAK_JWKS_URL) and caching keys
  - Verifying RS256 signature against the matching JWK
  - Validating iss == settings.KEYCLOAK_ISSUER_URL
  - Validating aud == settings.KEYCLOAK_CLIENT_ID
  - Validating exp / nbf
  - Mapping the token's `sub` (Keycloak user id) to a local User via
    User.external_id, provisioning the User row on first login if absent

Until implemented, SecurePAM must run with DEV_MODE=true.
"""

from app.auth.base import TokenIdentity, TokenValidator


class OIDCTokenValidator(TokenValidator):
    def validate(self, token: str) -> TokenIdentity:
        raise NotImplementedError(
            "OIDC/Keycloak token validation is not implemented yet. "
            "Run with DEV_MODE=true until Keycloak integration lands."
        )
