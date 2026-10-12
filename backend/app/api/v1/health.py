"""
Health check endpoints — no authentication required.

Provides service health for:
- Application
- Database
- Redis
- IdP (Keycloak)
- Vault
- Gateway (Guacamole)
"""

import time
from typing import List, Optional

import httpx
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_db
from app.schemas.common import DetailedHealthCheck, HealthCheck, LivenessCheck, ReadinessCheck, ServiceHealth
from app.secrets.openbao import runtime_vault_token

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """Basic health check — returns app status."""
    return HealthCheck(
        status="healthy",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
    )


@router.get("/health/live", response_model=LivenessCheck)
async def liveness_check():
    """
    Liveness probe — only confirms the application process can respond.
    Deliberately checks NO dependencies (DB/Redis/etc). A failing dependency
    should surface via /health/ready, not cause an orchestrator to restart
    an otherwise-healthy process.
    """
    return LivenessCheck(status="alive")


@router.get("/health/ready", response_model=ReadinessCheck)
async def readiness_check(response: Response, db: AsyncSession = Depends(get_db)):
    """
    Readiness probe — verifies the dependencies required to actually serve
    traffic (PostgreSQL, Redis). Returns 503 when not ready so load
    balancers / orchestrators can route around this instance.
    """
    checks: List[ServiceHealth] = [await _check_database(db), await _check_redis()]
    ready = all(c.status == "healthy" for c in checks)

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessCheck(status="ready" if ready else "not_ready", checks=checks)


@router.get("/health/detailed", response_model=DetailedHealthCheck)
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Detailed health check with all service statuses."""
    services: List[ServiceHealth] = []

    # Database
    db_health = await _check_database(db)
    services.append(db_health)

    # Redis
    redis_health = await _check_redis()
    services.append(redis_health)

    # IdP
    idp_health = _check_idp()
    services.append(idp_health)

    # Vault
    vault_health = _check_vault()
    services.append(vault_health)

    # Gateway
    gateway_health = _check_gateway()
    services.append(gateway_health)

    # SIEM
    siem_health = _check_siem()
    services.append(siem_health)

    # Overall status
    unhealthy = any(s.status == "unhealthy" for s in services)
    degraded = any(s.status == "degraded" for s in services)

    overall = "healthy"
    if unhealthy:
        overall = "unhealthy"
    elif degraded:
        overall = "degraded"

    return DetailedHealthCheck(
        status=overall,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
        services=services,
    )


async def _check_database(db: AsyncSession) -> ServiceHealth:
    """Check PostgreSQL connectivity."""
    try:
        start = time.monotonic()
        await db.execute(text("SELECT 1"))
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service="database",
            status="healthy",
            latency_ms=round(latency, 2),
        )
    except Exception as e:
        return ServiceHealth(
            service="database",
            status="unhealthy",
            details=str(e),
        )


async def _check_redis() -> ServiceHealth:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as aioredis

        start = time.monotonic()
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service="redis",
            status="healthy",
            latency_ms=round(latency, 2),
        )
    except Exception as e:
        return ServiceHealth(
            service="redis",
            status="unhealthy",
            details=str(e),
        )


def _check_idp() -> ServiceHealth:
    """Check IdP status."""
    if settings.DEV_MODE:
        return ServiceHealth(
            service="identity_provider",
            status="healthy",
            details="DEV_MODE: MockIdP active",
        )
    return ServiceHealth(
        service="identity_provider",
        status="degraded",
        details="Keycloak not yet configured",
    )


_OPENBAO_UP = {200, 429, 473}


def _check_vault(client: Optional[httpx.Client] = None) -> ServiceHealth:
    """Check OpenBao. Disabled mode does not call the network."""
    if not settings.VAULT_ENABLED and not runtime_vault_token():
        if settings.DEV_MODE:
            return ServiceHealth(
                service="vault",
                status="healthy",
                details="DEV_MODE: MockVault active",
            )
        return ServiceHealth(
            service="vault",
            status="degraded",
            details="OpenBao disabled",
        )

    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=2.0)
    status_code: Optional[int] = None
    try:
        response = client.get(f"{settings.VAULT_URL.rstrip('/')}/v1/sys/health")
        status_code = response.status_code
    except httpx.TimeoutException:
        return ServiceHealth(service="vault", status="unhealthy", details="OpenBao request timed out")
    except httpx.HTTPError:
        return ServiceHealth(service="vault", status="unhealthy", details="OpenBao unreachable")
    finally:
        if owns_client:
            client.close()

    if status_code in _OPENBAO_UP:
        return ServiceHealth(service="vault", status="healthy", details="OpenBao reachable")
    if status_code == 503:
        return ServiceHealth(service="vault", status="unhealthy", details="OpenBao sealed")
    return ServiceHealth(service="vault", status="unhealthy", details="OpenBao unavailable")


def _check_gateway() -> ServiceHealth:
    """Check session gateway status."""
    if settings.DEV_MODE:
        return ServiceHealth(
            service="gateway",
            status="healthy",
            details="DEV_MODE: MockSessionProvider active",
        )
    return ServiceHealth(
        service="gateway",
        status="degraded",
        details="Guacamole not yet configured",
    )


def _check_siem() -> ServiceHealth:
    """Check SIEM status."""
    if settings.DEV_MODE or not settings.WAZUH_ENABLED:
        return ServiceHealth(
            service="siem",
            status="healthy",
            details="DEV_MODE: MockSIEM active",
        )
    return ServiceHealth(
        service="siem",
        status="degraded",
        details="Wazuh not yet configured",
    )
