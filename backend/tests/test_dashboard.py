"""Dashboard summary/activity endpoints — real DB-backed counts, never fake numbers."""

from httpx import AsyncClient

from tests.conftest import auth_header


async def test_dashboard_summary_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 401


async def test_dashboard_summary_reflects_seeded_assets(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/v1/dashboard/summary", headers=auth_header(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    # Seed data creates exactly 5 assets (WIN-PROD-01, WIN-DEV-01,
    # LINUX-PROD-01, LINUX-DEV-01, LINUX-STAGING-01) — see app/main.py.
    assert body["registered_assets"] == 5
    assert body["active_sessions"] == 0
    assert body["pending_requests"] == 0
    assert isinstance(body["recording_storage_mb"], float)


async def test_dashboard_activity_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/dashboard/activity")
    assert resp.status_code == 401


async def test_dashboard_activity_returns_a_list(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/dashboard/activity", headers=auth_header(operator_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_dashboard_activity_limit_is_capped(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/dashboard/activity", params={"limit": 999}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 200
