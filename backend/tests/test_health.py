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


# --- SSH gateway: "healthy" must mean verified host keys, not a configured path ---

async def _ssh_gateway_status(client, token):
    resp = await client.get("/health/detailed", headers=auth_header(token))
    assert resp.status_code == 200
    return next(s for s in resp.json()["services"] if s["service"] == "gateway_ssh")


async def _enabled_ssh_assets(db_session):
    from sqlalchemy import select
    from app.models.asset import Asset
    rows = (await db_session.execute(
        select(Asset).where(Asset.protocol == "SSH", Asset.enabled == True, Asset.is_deleted == False)  # noqa: E712
    )).scalars().all()
    assert rows, "test database should contain SSH assets"
    return rows


async def test_ssh_gateway_healthy_only_when_every_ssh_target_has_a_trusted_key(
    client: AsyncClient, db_session, operator_token, tmp_path, monkeypatch
):
    import asyncssh
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    assets = await _enabled_ssh_assets(db_session)
    path = tmp_path / "known_hosts"
    monkeypatch.setenv("SECUREPAM_KNOWN_HOSTS_PATH", str(path))

    # Only the first target has a key: degraded, and the gap is named.
    path.write_text(f"{assets[0].hostname} {key}\n")
    partial = await _ssh_gateway_status(client, operator_token)
    if len(assets) > 1:
        assert partial["status"] == "degraded"
        assert assets[1].name in partial["details"]

    path.write_text("".join(f"{a.hostname} {key}\n" for a in assets))
    full = await _ssh_gateway_status(client, operator_token)
    assert full["status"] == "healthy"
    assert str(path) not in full["details"]


async def test_ssh_gateway_with_no_usable_host_keys_is_degraded_not_healthy(
    client: AsyncClient, db_session, operator_token, tmp_path, monkeypatch
):
    """A file that exists but yields no trusted keys (asyncssh skips junk lines)
    must not read as healthy: every SSH target is refused at connect time."""
    path = tmp_path / "known_hosts"
    path.write_text("this is not a known_hosts file ssh-ed25519 !!!notbase64\n")
    monkeypatch.setenv("SECUREPAM_KNOWN_HOSTS_PATH", str(path))
    assets = await _enabled_ssh_assets(db_session)
    result = await _ssh_gateway_status(client, operator_token)
    assert result["status"] == "degraded"
    assert f"{len(assets)} of {len(assets)}" in result["details"]
    assert str(path) not in result["details"]
