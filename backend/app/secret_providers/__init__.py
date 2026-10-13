"""
Secret providers — read-only access to the external secret store.

`get_secret_provider()` returns the one provider SECRET_PROVIDER selects.
Settings has already refused an incomplete OpenBao configuration at
startup, so there is no runtime fallback path here: "openbao" always
means OpenBao, and if it is down, callers fail closed.

Only app.services.credential_service should call read_secret(); nothing
under app.api may return what it yields.
"""

from functools import lru_cache

from app.core.config import Settings, settings
from app.secret_providers.base import (
    Credential,
    InvalidSecretReferenceError,
    MalformedSecretError,
    ProviderHealth,
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretProvider,
    SecretProviderConfigError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretRecord,
)
from app.secret_providers.mock import MockSecretProvider
from app.secret_providers.openbao import OpenBaoSecretProvider


def build_secret_provider(config: Settings) -> SecretProvider:
    if config.SECRET_PROVIDER == "mock":
        return MockSecretProvider(path_prefix=config.OPENBAO_SECRET_PATH_PREFIX)
    if config.SECRET_PROVIDER == "openbao":
        return OpenBaoSecretProvider(
            addr=config.OPENBAO_ADDR,
            token=config.OPENBAO_TOKEN,
            mount_point=config.OPENBAO_MOUNT_POINT,
            path_prefix=config.OPENBAO_SECRET_PATH_PREFIX,
            connect_timeout=config.OPENBAO_CONNECT_TIMEOUT_SECONDS,
            request_timeout=config.OPENBAO_REQUEST_TIMEOUT_SECONDS,
            ca_cert=config.OPENBAO_CA_CERT or None,
        )
    raise SecretProviderConfigError("Unknown SECRET_PROVIDER")


@lru_cache(maxsize=1)
def get_secret_provider() -> SecretProvider:
    return build_secret_provider(settings)


__all__ = [
    "Credential",
    "InvalidSecretReferenceError",
    "MalformedSecretError",
    "MockSecretProvider",
    "OpenBaoSecretProvider",
    "ProviderHealth",
    "SecretAccessDeniedError",
    "SecretNotFoundError",
    "SecretProvider",
    "SecretProviderConfigError",
    "SecretProviderError",
    "SecretProviderUnavailableError",
    "SecretRecord",
    "build_secret_provider",
    "get_secret_provider",
]
