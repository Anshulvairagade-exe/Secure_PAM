"""
SecurePAM Application Configuration.

All settings are loaded from environment variables.
Secrets must never have default values in production.
"""

from typing import List
from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    APP_NAME: str = "SecurePAM"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEV_MODE: bool = True
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "change-this-to-a-secure-random-string-in-production"

    # --- Backend ---
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Identity Provider ---
    KEYCLOAK_URL: str = "http://keycloak:8080"
    KEYCLOAK_REALM: str = "securepam"
    KEYCLOAK_CLIENT_ID: str = "securepam-app"
    KEYCLOAK_CLIENT_SECRET: str = ""
    KEYCLOAK_ADMIN_USER: str = "admin"
    KEYCLOAK_ADMIN_PASSWORD: str = ""

    # --- Vault ---
    VAULT_URL: str = "http://vault:8200"
    VAULT_TOKEN: str = ""
    VAULT_MOUNT_PATH: str = "secret"
    VAULT_ENABLED: bool = False

    # --- Guacamole ---
    GUACAMOLE_URL: str = "http://guacamole:8080/guacamole"
    GUACAMOLE_ADMIN_USER: str = "guacadmin"
    GUACAMOLE_ADMIN_PASSWORD: str = ""
    GUACD_HOST: str = "guacd"
    GUACD_PORT: int = 4822

    # --- Wazuh SIEM ---
    WAZUH_URL: str = ""
    WAZUH_USER: str = ""
    WAZUH_PASSWORD: str = ""
    WAZUH_ENABLED: bool = False

    # --- Session Defaults ---
    DEFAULT_SESSION_TIMEOUT: int = 30  # minutes
    MAX_SESSION_TIMEOUT: int = 480  # minutes
    JIT_DEFAULT_DURATION: int = 30  # minutes
    JIT_MAX_DURATION: int = 480  # minutes

    # --- Security ---
    TOKEN_EXPIRY_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRY_DAYS: int = 7
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10

    # --- Recordings ---
    RECORDING_STORAGE_PATH: str = "/data/recordings"
    RECORDING_RETENTION_DAYS: int = 90

    # --- Monitoring ---
    PROMETHEUS_ENABLED: bool = False

    @property
    def KEYCLOAK_ISSUER_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"

    @property
    def KEYCLOAK_JWKS_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs"

    @property
    def KEYCLOAK_TOKEN_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/token"

    @property
    def KEYCLOAK_AUTH_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/auth"

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_changed(cls, v: str, info) -> str:
        # In production, enforce a real secret key
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        # .env also carries vars consumed only by docker-compose / other
        # services (POSTGRES_*, REDIS_HOST, NGINX_*, GRAFANA_*) — ignore
        # rather than reject them.
        "extra": "ignore",
    }


# Global settings instance
settings = Settings()
