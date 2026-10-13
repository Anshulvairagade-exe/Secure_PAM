"""Application startup, DB/Redis connectivity, and health endpoint behavior."""

import pytest
from httpx import AsyncClient

from tests.conftest import auth_header


async def test_app_starts_and_root_health_responds(client: AsyncClient):
    """Covers 'application startup' — the ASGI app served a request at all."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["dev_mode"] is True


async def test_health_response_includes_request_id_header(client: AsyncClient):
    resp = await client.get("/health")
    assert "x-request-id" in resp.headers


async def test_liveness_never_touches_dependencies(client: AsyncClient):
    """/health/live must succeed even if it never checks DB/Redis."""
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


async def test_readiness_reports_database_and_redis_healthy(client: AsyncClient):
    """Covers 'database connection' — readiness actually queries Postgres + Redis."""
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    services = {c["service"]: c["status"] for c in body["checks"]}
    assert services["database"] == "healthy"
    assert services["redis"] == "healthy"


async def test_detailed_health_requires_authentication(client: AsyncClient):
    resp = await client.get("/health/detailed")
    assert resp.status_code == 401


async def test_detailed_health_reports_dev_mode_truthfully(client: AsyncClient, operator_token, tmp_path, monkeypatch):
    """Development stand-ins are reported as mock and undeployed gateways as
    not_configured, never as healthy; only real failures degrade the overall status."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(tmp_path / "recordings"))
    monkeypatch.delenv("SECUREPAM_KNOWN_HOSTS_PATH", raising=False)
    resp = await client.get("/health/detailed", headers=auth_header(operator_token))
    assert resp.status_code == 200
    body = resp.json()
    services = {s["service"]: s["status"] for s in body["services"]}
    assert services["database"] == "healthy"
    assert services["redis"] == "healthy"
    assert services["identity_provider"] == "mock"
    assert services["vault"] == "mock"
    assert services["gateway_ssh"] == "not_configured"
    assert services["gateway_rdp"] == "not_configured"
    assert services["gateway_web"] == "not_configured"
    assert services["siem"] == "not_configured"
    assert services["recording_storage"] == "healthy"
    assert body["status"] == "healthy"


async def test_detailed_health_reports_unwritable_recording_storage(client: AsyncClient, operator_token, tmp_path, monkeypatch):
    from app.core.config import settings
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(locked / "recordings"))
    try:
        body = (await client.get("/health/detailed", headers=auth_header(operator_token))).json()
        storage = next(s for s in body["services"] if s["service"] == "recording_storage")
        assert storage["status"] == "unhealthy" and body["status"] == "unhealthy"
    finally:
        locked.chmod(0o700)


async def test_health_preserves_caller_supplied_request_id(client: AsyncClient):
    request_id = "securepam-test-request-123"

    resp = await client.get(
        "/health",
        headers={"X-Request-ID": request_id},
    )

    assert resp.status_code == 200
    assert resp.headers["x-request-id"] == request_id


async def test_health_generates_request_id_when_missing(client: AsyncClient):
    resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.headers["x-request-id"]
    assert len(resp.headers["x-request-id"]) == 36
