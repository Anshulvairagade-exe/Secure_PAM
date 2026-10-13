"""
System settings summary — the non-secret configuration a signed-in user may
see on the Settings page.

Only behaviour-relevant values are returned: no passwords, tokens, keys,
connection strings, hostnames or filesystem paths. Settings are changed
through deployment configuration (environment variables), not at runtime,
so this endpoint is read-only for every role.
"""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.config import settings
from app.core.deps import get_current_active_user
from app.models.user import User
from app.services.terminal_recorder import storage_writable

router = APIRouter(prefix="/settings", tags=["Settings"])


class SystemSettings(BaseModel):
    environment: str
    version: str
    dev_mode: bool
    authentication: str
    secret_provider: str
    jit_default_minutes: int
    jit_max_minutes: int
    session_default_timeout_minutes: int
    session_max_timeout_minutes: int
    rate_limit_per_minute: int
    rate_limit_login_per_minute: int
    recording_storage_writable: bool
    recording_retention_days: Optional[int]
    ssh_recording_format: str
    managed_by: str


@router.get("/summary", response_model=SystemSettings)
async def get_settings_summary(_: User = Depends(get_current_active_user)) -> SystemSettings:
    return SystemSettings(
        environment=settings.ENVIRONMENT,
        version=settings.APP_VERSION,
        dev_mode=settings.DEV_MODE,
        authentication="development accounts (DEV_MODE)" if settings.DEV_MODE else "Keycloak OIDC",
        secret_provider=settings.SECRET_PROVIDER,
        jit_default_minutes=settings.JIT_DEFAULT_DURATION,
        jit_max_minutes=settings.JIT_MAX_DURATION,
        session_default_timeout_minutes=settings.DEFAULT_SESSION_TIMEOUT,
        session_max_timeout_minutes=settings.MAX_SESSION_TIMEOUT,
        rate_limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
        rate_limit_login_per_minute=settings.RATE_LIMIT_AUTH_PER_MINUTE,
        recording_storage_writable=storage_writable(),
        recording_retention_days=getattr(settings, "RECORDING_RETENTION_DAYS", None),
        ssh_recording_format="asciicast v2 (terminal output and resizes; keystrokes not captured)",
        managed_by="Deployment configuration (environment variables); read-only at runtime",
    )
