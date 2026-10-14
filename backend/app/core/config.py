"""
SecurePAM Application Configuration.

All settings are loaded from environment variables.
Secrets must never have default values in production.
"""

import re
from pathlib import Path
from typing import Optional, List, Literal
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings

from pydantic import SecretStr, field_validator, model_validator

# backend/ — .env is resolved relative to this, not to the process CWD, so
# `uvicorn` / `alembic` / `pytest` all read the same file no matter where
# they're launched from.
BACKEND_DIR = Path(__file__).resolve().parents[2]

# One or more slash-separated segments of safe characters. Used for the KV
# mount point and the server-side secret path prefix — never "..", never a
# leading/trailing slash.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")


_DEV_MODE_ENVIRONMENTS = {"development", "test"}
_PLACEHOLDER_SECRET_KEY = "change-this-to-a-secure-random-string-in-production"
_MIN_SECRET_KEY_LENGTH = 32


class SettingsError(Exception):
    """Invalid configuration. Deliberately NOT a ValueError: pydantic wraps
    ValueErrors in a ValidationError whose message embeds the raw input
    (including OPENBAO_TOKEN); a non-ValueError propagates as-is, carrying
    only the sanitized message built below."""



class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    APP_NAME: str = "SecurePAM"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEV_MODE: bool = True
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = _PLACEHOLDER_SECRET_KEY

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
    KEYCLOAK_INTERNAL_URL: str = ""
    KEYCLOAK_REALM: str = "securepam"
    KEYCLOAK_CLIENT_ID: str = "securepam-app"
    KEYCLOAK_CLIENT_SECRET: str = ""
    KEYCLOAK_ADMIN_USER: str = "admin"
    KEYCLOAK_ADMIN_PASSWORD: str = ""

    # --- Keycloak MFA Event Synchronization ---
    # Confidential client with a service account holding ONLY realm-management/view-events.
    # The secret belongs in protected local/runtime configuration, never in Git.
    KEYCLOAK_AUDIT_CLIENT_ID: str = "securepam-audit-reader"
    KEYCLOAK_AUDIT_CLIENT_SECRET: SecretStr = SecretStr("")
    # Off unless configured: the loop needs the audit-reader secret (the package's intended value is true).
    KEYCLOAK_MFA_SYNC_ENABLED: bool = False
    KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS: int = 60
    KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS: int = 1

    # --- Secret provider (credential retrieval) ---
    # "mock" serves fake credentials only and is refused in production.
    # "openbao" requires OPENBAO_ADDR + OPENBAO_TOKEN; if either is missing
    # or invalid, startup fails — there is no silent fallback to mock.
    SECRET_PROVIDER: Literal["mock", "openbao"] = "mock"
    OPENBAO_ADDR: str = ""
    OPENBAO_MOUNT_POINT: str = "secret"
    OPENBAO_TOKEN: SecretStr = SecretStr("")
    # Every credential reference must live under <mount>/data/<prefix>/...
    OPENBAO_SECRET_PATH_PREFIX: str = "securepam"
    OPENBAO_CONNECT_TIMEOUT_SECONDS: float = 3.0
    OPENBAO_REQUEST_TIMEOUT_SECONDS: float = 5.0
    # Optional CA bundle path for a TLS-terminated OpenBao; empty = system CAs.
    OPENBAO_CA_CERT: str = ""
    # Optional SEPARATE credential-writer identity (securepam-writer policy: create+update on the
    # registered paths only, no read). Used only by the admin credential-provisioning endpoints;
    # empty = provisioning disabled (fails closed). Never the reader token, never sent to a browser.
    OPENBAO_WRITER_TOKEN: SecretStr = SecretStr("")
    # Where administrators open the OpenBao web UI (private address: SSM port-forward / VPN).
    # Shown as a link only; no token is ever attached.
    OPENBAO_UI_URL: str = ""
    # Secret names an ASSET may be provisioned/bound to through the integrated workflow
    # (<prefix>/assets/<name>); must match the exact paths in the reader and writer policies.
    ASSET_CREDENTIAL_SECRET_NAMES: list[str] = ["win11-lab", "kali"]
    # Secret names an APPLICATION may be bound to (<prefix>/assets/<name>). Server-side allowlist:
    # the admin API refuses any other name, and each name binds to at most one application. Must
    # match the exact paths in infrastructure/openbao/aws/policies/*.hcl.
    APPLICATION_CREDENTIAL_SECRET_NAMES: list[str] = ["wazuh-dashboard"]

    # --- Vault (legacy, superseded by SECRET_PROVIDER / OPENBAO_*) ---
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
    # Default per-user cap on concurrent live privileged sessions; an admin can
    # override it at runtime (stored in app_settings).
    MAX_CONCURRENT_SESSIONS: int = 2

    # --- RDP gateway (Apache Guacamole's guacd) ---
    # RDP launches are refused (503) unless this is true. GUACD_HOST/GUACD_PORT (above) say where guacd
    # listens; with a host-run backend and the isolated compose file that is 127.0.0.1:4822.
    RDP_GATEWAY_ENABLED: bool = False
    # Where guacd writes recordings *inside its container* (a bind mount of RDP_RECORDING_PATH).
    GUACD_RECORDING_PATH: str = "/recordings"
    # The same directory as seen by the backend. Defaults to <RECORDING_STORAGE_PATH>/rdp.
    RDP_RECORDING_PATH: Optional[str] = None
    # NLA authenticates the user to the server before a desktop is sent (and, via CredSSP,
    # binds the credential exchange to the TLS key). Windows lab servers use self-signed
    # certificates, so certificate-chain validation is off by default; see README.
    RDP_SECURITY: str = "nla"
    RDP_IGNORE_CERT: bool = True

    # --- Isolated browser (infrastructure/browser-isolation) ---
    # Web (HTTP/HTTPS) launches are refused (503) unless enabled. The daemon's management API and VNC
    # ports are published on loopback only; its bearer token is read from a 0600 file, never from source.
    BROWSER_ISOLATION_ENABLED: bool = False
    BROWSER_ISOLATION_URL: str = "http://127.0.0.1:6090"
    BROWSER_ISOLATION_TOKEN_FILE: Optional[str] = None
    BROWSER_ISOLATION_VNC_HOST: str = "127.0.0.1"

    # --- SIEM event sink ---
    # Structured, secret-free JSON lines for every audit event, for a Wazuh agent's <localfile>
    # (log_format json) to ship. Unset = disabled.
    SIEM_EVENT_LOG_PATH: Optional[str] = None

    # --- Risk Engine (project-specific scoring choices) ---
    # Defaults equal app.risk.engine.RISK_WEIGHTS; RiskConfiguration validates
    # them at startup (unknown factors, negative weights or misordered
    # thresholds stop the app).
    RISK_WEIGHT_PRODUCTION_ASSET: int = 30
    RISK_WEIGHT_CRITICAL_ASSET: int = 25
    RISK_WEIGHT_HIGH_CRITICALITY: int = 15
    RISK_WEIGHT_SENSITIVE_APPLICATION: int = 20
    RISK_WEIGHT_HIGH_PRIVILEGE_ROLE: int = 20
    RISK_WEIGHT_OUTSIDE_BUSINESS_HOURS: int = 20
    RISK_WEIGHT_UNKNOWN_CONTEXT: int = 20
    RISK_WEIGHT_REPEATED_AUTH_FAILURE: int = 20
    RISK_WEIGHT_UNUSUAL_ACCESS_PATTERN: int = 20
    RISK_WEIGHT_LONG_DURATION: int = 10
    RISK_ENABLE_PRODUCTION_ASSET: bool = True
    RISK_ENABLE_CRITICAL_ASSET: bool = True
    RISK_ENABLE_HIGH_CRITICALITY: bool = True
    RISK_ENABLE_SENSITIVE_APPLICATION: bool = True
    RISK_ENABLE_HIGH_PRIVILEGE_ROLE: bool = True
    RISK_ENABLE_OUTSIDE_BUSINESS_HOURS: bool = True
    RISK_ENABLE_UNKNOWN_CONTEXT: bool = True
    RISK_ENABLE_REPEATED_AUTH_FAILURE: bool = True
    RISK_ENABLE_UNUSUAL_ACCESS_PATTERN: bool = True
    RISK_ENABLE_LONG_DURATION: bool = True
    RISK_HIGH_PRIVILEGE_ROLES: List[str] = ["ADMIN"]
    RISK_LONG_DURATION_THRESHOLD_MINUTES: int = 60
    RISK_MEDIUM_THRESHOLD: int = 30
    RISK_HIGH_THRESHOLD: int = 60
    RISK_CRITICAL_THRESHOLD: int = 80

    # --- Security ---
    TOKEN_EXPIRY_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRY_DAYS: int = 7
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10

    # --- Recordings ---
    RECORDING_STORAGE_PATH: str = "/data/recordings"
    RECORDING_RETENTION_DAYS: int = 90

    # Seed the fictional sample assets/applications on first DEV_MODE boot.
    # Off by default: pages show real, user-registered targets only.
    SEED_SAMPLE_TARGETS: bool = False

    # --- Monitoring ---
    PROMETHEUS_ENABLED: bool = False

    @property
    def KEYCLOAK_ISSUER_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"

    @property
    def KEYCLOAK_JWKS_URL(self) -> str:
        base_url = self.KEYCLOAK_INTERNAL_URL or self.KEYCLOAK_URL
        return (
            f"{base_url}/realms/{self.KEYCLOAK_REALM}"
            "/protocol/openid-connect/certs"
        )

    @property
    def KEYCLOAK_TOKEN_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/token"

    @property
    def KEYCLOAK_AUTH_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/auth"


    @field_validator("SECRET_PROVIDER", mode="before")
    @classmethod
    def normalize_secret_provider(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    # Secrets may be delivered as files (Docker/ECS secrets, or a file rendered from AWS Secrets
    # Manager at boot) instead of environment variables: <NAME>_FILE points at a file readable only
    # by its owner. An explicit environment value wins; a world/group-readable file is refused.
    KEYCLOAK_AUDIT_CLIENT_SECRET_FILE: str = ""
    OPENBAO_TOKEN_FILE: str = ""
    OPENBAO_WRITER_TOKEN_FILE: str = ""

    @model_validator(mode="after")
    def load_secret_files(self) -> "Settings":
        import os
        import stat
        for name in ("KEYCLOAK_AUDIT_CLIENT_SECRET", "OPENBAO_TOKEN", "OPENBAO_WRITER_TOKEN"):
            path = getattr(self, f"{name}_FILE")
            if not path or getattr(self, name).get_secret_value():
                continue
            try:
                info = os.stat(path)
                if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise SettingsError(f"{name}_FILE must not be readable by group/others (chmod 600)")
                with open(path, "r", encoding="utf-8") as handle:
                    value = handle.read().strip()
            except OSError:
                raise SettingsError(f"{name}_FILE cannot be read") from None
            if not value:
                raise SettingsError(f"{name}_FILE is empty")
            object.__setattr__(self, name, SecretStr(value))
        return self

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        # Messages name the offending setting but never echo a token value.
        errors: List[str] = []
        environment = self.ENVIRONMENT.strip().lower()
        production = environment == "production"
        protected_environment = environment in {"production", "staging"}

        # DEV_MODE enables /auth/login, the DevAuth HS256 validator and the
        # seeded admin123/operator123 accounts. Outside local development
        # or the test suite that is an authentication bypass, so refuse it.
        if self.DEV_MODE and self.ENVIRONMENT.lower() not in _DEV_MODE_ENVIRONMENTS:
            errors.append("DEV_MODE=true is only allowed when ENVIRONMENT is development or test")
        if protected_environment and (
            not self.SECRET_KEY.strip()
            or self.SECRET_KEY == _PLACEHOLDER_SECRET_KEY
            or (production and len(self.SECRET_KEY) < _MIN_SECRET_KEY_LENGTH)
        ):
            errors.append(
                "SECRET_KEY must be changed, non-empty, and sufficiently long in production; "
                "it must be non-empty and non-placeholder in staging"
            )

        if self.SECRET_PROVIDER == "mock":
            if production:
                errors.append("SECRET_PROVIDER=mock is not allowed when ENVIRONMENT=production")
        else:
            token = self.OPENBAO_TOKEN.get_secret_value()
            if not token.strip():
                errors.append("OPENBAO_TOKEN is required when SECRET_PROVIDER=openbao")
            elif not token.isprintable() or any(c.isspace() for c in token):
                errors.append("OPENBAO_TOKEN contains whitespace or non-printable characters")

            if not self.OPENBAO_ADDR.strip():
                errors.append("OPENBAO_ADDR is required when SECRET_PROVIDER=openbao")
            else:
                try:
                    parts = urlsplit(self.OPENBAO_ADDR)
                    valid = (
                        parts.scheme in ("http", "https")
                        and bool(parts.hostname)
                        and parts.path in ("", "/")
                        and not parts.query
                        and not parts.fragment
                        and parts.username is None
                        and parts.password is None
                    )
                    parts.port  # raises ValueError on a malformed port
                except ValueError:
                    valid = False
                if not valid:
                    errors.append("OPENBAO_ADDR must be a plain http(s)://host[:port] URL")
                elif production and parts.scheme != "https":
                    errors.append("OPENBAO_ADDR must use https when ENVIRONMENT=production")

            if not _SAFE_PATH_RE.match(self.OPENBAO_MOUNT_POINT) or ".." in self.OPENBAO_MOUNT_POINT:
                errors.append("OPENBAO_MOUNT_POINT is invalid")
            if not _SAFE_PATH_RE.match(self.OPENBAO_SECRET_PATH_PREFIX) or ".." in self.OPENBAO_SECRET_PATH_PREFIX:
                errors.append("OPENBAO_SECRET_PATH_PREFIX is invalid")
            if self.OPENBAO_CONNECT_TIMEOUT_SECONDS <= 0 or self.OPENBAO_REQUEST_TIMEOUT_SECONDS <= 0:
                errors.append("OPENBAO_*_TIMEOUT_SECONDS must be positive")

        writer = self.OPENBAO_WRITER_TOKEN.get_secret_value()
        if writer:
            if self.SECRET_PROVIDER != "openbao":
                errors.append("OPENBAO_WRITER_TOKEN requires SECRET_PROVIDER=openbao")
            elif writer == self.OPENBAO_TOKEN.get_secret_value():
                errors.append("OPENBAO_WRITER_TOKEN must be a separate identity from OPENBAO_TOKEN")
        if self.OPENBAO_UI_URL and not re.match(r"^https://[A-Za-z0-9.\-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$", self.OPENBAO_UI_URL):
            errors.append("OPENBAO_UI_URL must be a plain https:// URL without credentials or query")
        for name in self.ASSET_CREDENTIAL_SECRET_NAMES + self.APPLICATION_CREDENTIAL_SECRET_NAMES:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name or "") or ".." in name:
                errors.append("*_CREDENTIAL_SECRET_NAMES must be single safe path segments")
                break

        if errors:
            raise SettingsError("; ".join(errors))

        return self

    model_config = {
        "env_file": str(BACKEND_DIR / ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        # .env also carries vars consumed only by docker-compose / other
        # services (POSTGRES_*, REDIS_HOST, NGINX_*, GRAFANA_*) — ignore
        # rather than reject them.
        "extra": "ignore",
    }


# Global settings instance
settings = Settings()
