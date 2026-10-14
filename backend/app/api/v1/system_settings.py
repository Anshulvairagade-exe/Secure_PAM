"""
System settings summary — the non-secret configuration a signed-in user may
see on the Settings page.

Only behaviour-relevant values are returned: no passwords, tokens, keys,
connection strings, hostnames or filesystem paths. Settings are changed
through deployment configuration (environment variables), not at runtime,
so this endpoint is read-only for every role.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_current_active_user, get_db
from app.services.session_policy import MAX_LIMIT, MIN_LIMIT, get_limit, set_limit
from app.models.user import User
from app.services.terminal_recorder import storage_writable
from app.secret_providers.writer import writer_status

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
    # Integration facts only (booleans / public URLs), never secrets or internal paths.
    mfa_provider: str
    mfa_self_service: bool  # authenticator managed in the Keycloak account console (no URL here: see /auth/config)
    mfa_failure_sync_enabled: bool
    siem_forwarding_enabled: bool
    credential_provisioning_configured: bool
    openbao_ui_configured: bool


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
        mfa_provider="none (DEV_MODE development accounts)" if settings.DEV_MODE else "Keycloak (TOTP)",
        mfa_self_service=not settings.DEV_MODE,
        mfa_failure_sync_enabled=settings.KEYCLOAK_MFA_SYNC_ENABLED,
        siem_forwarding_enabled=bool(settings.SIEM_EVENT_LOG_PATH),
        credential_provisioning_configured=writer_status()[0],
        openbao_ui_configured=bool(settings.OPENBAO_UI_URL),
    )


class SessionPolicy(BaseModel):
    max_concurrent_sessions: int
    min_allowed: int = MIN_LIMIT
    max_allowed: int = MAX_LIMIT
    default: int


class SessionPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_concurrent_sessions: int = Field(ge=MIN_LIMIT, le=MAX_LIMIT)


@router.get("/session-policy", response_model=SessionPolicy)
async def get_session_policy(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    return SessionPolicy(max_concurrent_sessions=await get_limit(db), default=settings.MAX_CONCURRENT_SESSIONS)


@router.put("/session-policy", response_model=SessionPolicy)
async def update_session_policy(
    body: SessionPolicyUpdate, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("settings", "update")),
):
    """Per-user cap on concurrent live sessions. Applies to the next launch; sessions already
    running are not ended. Audited with before/after."""
    before = await set_limit(db, body.max_concurrent_sessions, actor)
    await write_audit_log(
        db, actor=actor, action="SESSION_POLICY_CHANGED", target_type="settings",
        target_id="max_concurrent_sessions", source_ip=client_ip(request), result="SUCCESS", severity="HIGH",
        metadata={"before": before, "after": body.max_concurrent_sessions},
    )
    await db.commit()
    return SessionPolicy(max_concurrent_sessions=body.max_concurrent_sessions, default=settings.MAX_CONCURRENT_SESSIONS)
