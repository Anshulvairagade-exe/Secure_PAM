"""
Credential reference endpoints (HTTP) and the no-leak guarantee across HTTP
responses: RBAC, server-derived paths (a client can't pick one), and that
neither these endpoints, health checks nor audit listings ever surface a
secret value — there is no route that returns one.
"""

import pytest
from sqlalchemy import select

from app.main import app
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.vault_ref import VaultRef
from tests.conftest import auth_header

PASSWORD = "PW-CANARY-http-not-real"


async def _asset_id(db_session, name="LINUX-DEV-01") -> str:
    result = await db_session.execute(select(Asset).where(Asset.name == name))
    return str(result.scalar_one().id)


def url(asset_id: str) -> str:
    return f"/api/v1/assets/{asset_id}/credential-ref"


async def test_admin_sets_reference_with_server_derived_path(client, db_session, admin_token):
    asset_id = await _asset_id(db_session)
    r = await client.put(url(asset_id), headers=auth_header(admin_token),
                         json={"secret_name": "test-linux-01", "username": "fakeuser"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vault_path"] == "securepam/assets/test-linux-01"
    assert body["provider"] == "mock"  # whatever SECRET_PROVIDER is running — never client-chosen
    assert body["is_active"] is True
    assert not ({"password", "secret", "token", "value"} & set(body))

    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_REF_SET"))).scalar_one()
    assert audit.details["secret_reference"] == "securepam/assets/test-linux-01"

    r = await client.get(url(asset_id), headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["id"] == body["id"]


async def test_replacing_reference_deactivates_previous(client, db_session, admin_token):
    asset_id = await _asset_id(db_session)
    for name in ("first", "second"):
        assert (await client.put(url(asset_id), headers=auth_header(admin_token), json={"secret_name": name})).status_code == 200
    refs = (await db_session.execute(select(VaultRef))).scalars().all()
    assert sorted((r.vault_path, r.is_active) for r in refs) == [
        ("securepam/assets/first", False), ("securepam/assets/second", True),
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"secret_name": "../../sys/mounts"},
        {"secret_name": "a/b"},
        {"secret_name": ".."},
        {"secret_name": ""},
        {"secret_name": "ok", "vault_path": "secret/data/anything"},
        {"secret_name": "ok", "provider": "openbao"},
        {"secret_name": "ok", "password": PASSWORD},
        {"secret_name": "ok", "secret_type": "ROOT_TOKEN"},
        {"secret_name": "ok", "secret_version": 0},
    ],
)
async def test_client_cannot_choose_path_provider_or_send_secret(client, db_session, admin_token, payload):
    r = await client.put(url(await _asset_id(db_session)), headers=auth_header(admin_token), json=payload)
    assert r.status_code == 422
    assert PASSWORD not in r.text
    assert (await db_session.execute(select(VaultRef))).scalars().all() == []


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token", "auditor_token"])
async def test_non_admins_cannot_manage_or_read_references(client, db_session, request, token_fixture):
    token = request.getfixturevalue(token_fixture)
    asset_id = await _asset_id(db_session)
    headers = auth_header(token)
    assert (await client.put(url(asset_id), headers=headers, json={"secret_name": "x"})).status_code == 403
    assert (await client.get(url(asset_id), headers=headers)).status_code == 403
    assert (await client.delete(url(asset_id), headers=headers)).status_code == 403


async def test_unauthenticated_rejected(client, db_session):
    assert (await client.get(url(await _asset_id(db_session)))).status_code == 401


async def test_unknown_asset_404(client, admin_token):
    r = await client.put(url("00000000-0000-0000-0000-000000000000"), headers=auth_header(admin_token),
                         json={"secret_name": "x"})
    assert r.status_code == 404


async def test_deactivate_reference(client, db_session, admin_token):
    asset_id = await _asset_id(db_session)
    await client.put(url(asset_id), headers=auth_header(admin_token), json={"secret_name": "x"})
    assert (await client.delete(url(asset_id), headers=auth_header(admin_token))).status_code == 204
    assert (await client.get(url(asset_id), headers=auth_header(admin_token))).status_code == 404
    assert (await client.delete(url(asset_id), headers=auth_header(admin_token))).status_code == 404


def test_no_route_exposes_credentials():
    """Structural guard: no API path is a credential-retrieval endpoint."""
    paths = [getattr(r, "path", "") for r in app.routes]
    for p in paths:
        lowered = p.lower()
        assert not any(w in lowered for w in ("checkout", "reveal", "/secret", "password", "/credentials")), p


async def test_secret_never_appears_in_http_responses(client, db_session, admin_token):
    """After a real (mock-provider) checkout, sweep every read surface."""
    from tests.test_credential_service import _scenario
    from app.secret_providers import MockSecretProvider
    from app.services.credential_service import CredentialService

    req = await _scenario(db_session)
    provider = MockSecretProvider({"securepam/assets/linux-dev-01": {"password": PASSWORD}})
    async with CredentialService(provider=provider).checkout(db_session, req) as cred:
        assert cred.reveal() == PASSWORD

    asset_id = str(req.asset_id)
    for path in ("/health", "/health/detailed", url(asset_id), "/api/v1/assets/" + asset_id, "/api/v1/audit/"):
        r = await client.get(path, headers=auth_header(admin_token))
        assert PASSWORD not in r.text, path


async def test_detailed_health_reports_mock_provider(client):
    r = await client.get("/health/detailed")
    vault = next(s for s in r.json()["services"] if s["service"] == "vault")
    assert vault["status"] == "healthy"
    assert vault["details"].startswith("mock:")
