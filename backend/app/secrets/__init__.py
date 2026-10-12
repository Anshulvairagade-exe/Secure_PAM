"""OpenBao-backed secret retrieval."""

from app.secrets.base import (
    SecretDeniedError,
    SecretError,
    SecretMaterial,
    SecretNotFoundError,
    SecretProvider,
    SecretTimeoutError,
    SecretUnauthenticatedError,
    SecretUnavailableError,
)
from app.secrets.openbao import DisabledSecretProvider, OpenBaoSecretProvider, get_secret_provider
from app.secrets.retrieval import CredentialRetrievalService

__all__ = [
    "CredentialRetrievalService",
    "DisabledSecretProvider",
    "OpenBaoSecretProvider",
    "SecretDeniedError",
    "SecretError",
    "SecretMaterial",
    "SecretNotFoundError",
    "SecretProvider",
    "SecretTimeoutError",
    "SecretUnauthenticatedError",
    "SecretUnavailableError",
    "get_secret_provider",
]
