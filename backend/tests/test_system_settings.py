"""Settings summary: authenticated, read-only, and free of secrets."""

from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import auth_header


async def test_settings_summary_requires_authentication(client: AsyncClient):
    assert (await client.get("/api/v1/settings/summary")).status_code == 401


async def test_settings_summary_exposes_no_secrets(client: AsyncClient, operator_token, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(tmp_path / "recordings"))
    r = await client.get("/api/v1/settings/summary", headers=auth_header(operator_token))
    assert r.status_code == 200
    body = r.json()
    assert body["dev_mode"] is True and body["recording_storage_writable"] is True
    for secret in (settings.SECRET_KEY, settings.DATABASE_URL, settings.REDIS_URL, str(tmp_path)):
        assert secret not in r.text
    assert not any(k for k in body if any(w in k.lower() for w in ("password", "token", "secret_key", "url", "path")))


async def test_settings_summary_is_read_only(client: AsyncClient, admin_token):
    for method in ("PUT", "PATCH", "POST", "DELETE"):
        r = await client.request(method, "/api/v1/settings/summary", headers=auth_header(admin_token))
        assert r.status_code == 405
