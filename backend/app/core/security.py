"""
Security utilities — token validation, password hashing, and cryptographic helpers.

IMPORTANT: This module does NOT implement custom cryptography.
It wraps mature libraries (python-jose, passlib) for standard operations.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# Password hashing context — bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dev-mode signing key (in production, OIDC tokens are validated via JWKS)
DEV_JWT_ALGORITHM = "HS256"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Create a bcrypt hash of a password."""
    return pwd_context.hash(password)


def create_dev_access_token(
    subject: str,
    roles: list[str] | None = None,
    extra_claims: Dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token for DEV_MODE only.
    In production, tokens come from Keycloak/OIDC — not created here.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.TOKEN_EXPIRY_MINUTES)

    to_encode: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "iss": "securepam-dev",
        "aud": settings.KEYCLOAK_CLIENT_ID,
        "jti": str(uuid.uuid4()),
        "type": "access",
    }

    if roles:
        to_encode["realm_access"] = {"roles": roles}

    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=DEV_JWT_ALGORITHM)


def create_dev_refresh_token(subject: str) -> str:
    """Create a refresh token for DEV_MODE only."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRY_DAYS)

    to_encode = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "iss": "securepam-dev",
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=DEV_JWT_ALGORITHM)


def decode_dev_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a dev-mode JWT token.
    Raises JWTError if invalid.
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[DEV_JWT_ALGORITHM],
        audience=settings.KEYCLOAK_CLIENT_ID,
    )


def generate_request_number() -> str:
    """Generate a unique request number like REQ-XXXXX."""
    short_id = uuid.uuid4().hex[:5].upper()
    return f"REQ-{short_id}"


def generate_session_number() -> str:
    """Generate a unique session number like SES-XXXXX."""
    short_id = uuid.uuid4().hex[:5].upper()
    return f"SES-{short_id}"


def generate_event_id() -> str:
    """Generate a unique audit event ID like EVT-XXXXXXXX."""
    short_id = uuid.uuid4().hex[:8].upper()
    return f"EVT-{short_id}"
