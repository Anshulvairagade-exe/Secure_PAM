"""
Application credential references (Wazuh dashboard): the binding is admin-only, resolves server-side
to an ALLOWLISTED path, can never be pointed at an arbitrary OpenBao location, binds one credential to
one application, is audited without secret values, and the readiness check fails closed.
"""

import pytest
from sqlalchemy import select

from app.models.application import Application
from app.models.audit import AuditLog
from app.models.vault_ref import VaultRef
from tests.conftest import auth_header

PASSWORD = "PW-CANARY-wazuh-not-real"


async def _app(db, name="Cloud Wazuh Dashboard", host="3.104.196.100"):
    a = Application(name=name, hostname=host, port=443, protocol="HTTPS", target_url=f"https://{host}:443/app/login",
                    start_path="/app/login", environment="PRODUCTION", criticality="HIGH",
                    access_mode="ISOLATED_BROWSER", enabled=True, approval_required=True,
                    recording_required=False, session_timeout=30)
    db.add(a)
    await db.commit()
    return str(a.id)


def url(app_id: str) -> str:
    return f"/api/v1/applications/{app_id}/credential-ref"


async def test_admin_binds_wazuh_to_its_registered_reference(client, db_session, admin_token):
    app_id = await _app(db_session)
    r = await client.put(url(app_id), headers=auth_header(admin_token),
                         json={"secret_name": "wazuh-dashboard", "username": "wazuh-operator"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vault_path"] == "securepam/assets/wazuh-dashboard"
    assert body["application_id"] == app_id and body["is_active"] is True
    assert not ({"password", "secret", "token", "value"} & set(body))
    audit = (await db_session.execute(select(AuditLog).where(
        AuditLog.action == "CREDENTIAL_REF_SET", AuditLog.result == "SUCCESS"))).scalar_one()
    assert audit.target_type == "application" and audit.details["secret_reference"] == "securepam/assets/wazuh-dashboard"
    r = await client.get(url(app_id), headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["id"] == body["id"]


@pytest.mark.parametrize("payload", [
    {"secret_name": "kali"},                                   # a real path, but not an application credential
    {"secret_name": "win11-lab"},
    {"secret_name": "anything-else"},
    {"secret_name": "../../sys/mounts"},
    {"secret_name": "wazuh-dashboard/../kali"},
    {"secret_name": "wazuh-dashboard", "vault_path": "secret/data/securepam/assets/kali"},
    {"secret_name": "wazuh-dashboard", "provider": "openbao"},
    {"secret_name": "wazuh-dashboard", "password": PASSWORD},
])
async def test_caller_cannot_choose_an_arbitrary_path(client, db_session, admin_token, payload):
    app_id = await _app(db_session)
    r = await client.put(url(app_id), headers=auth_header(admin_token), json=payload)
    assert r.status_code == 422
    assert PASSWORD not in r.text
    assert (await db_session.execute(select(VaultRef))).scalars().all() == []


async def test_non_allowlisted_name_is_refused_and_audited(client, db_session, admin_token):
    app_id = await _app(db_session)
    r = await client.put(url(app_id), headers=auth_header(admin_token), json={"secret_name": "kali"})
    assert r.status_code == 422
    denied = (await db_session.execute(select(AuditLog).where(AuditLog.result == "DENIED"))).scalar_one()
    assert denied.details["reason"] == "SECRET_NAME_NOT_ALLOWLISTED"


async def test_one_credential_binds_to_one_application(client, db_session, admin_token):
    first = await _app(db_session)
    second = await _app(db_session, name="Other Dashboard", host="3.104.196.101")
    assert (await client.put(url(first), headers=auth_header(admin_token),
                             json={"secret_name": "wazuh-dashboard"})).status_code == 200
    r = await client.put(url(second), headers=auth_header(admin_token), json={"secret_name": "wazuh-dashboard"})
    assert r.status_code == 409
    # Re-binding the same application is fine (replaces its own reference).
    assert (await client.put(url(first), headers=auth_header(admin_token),
                             json={"secret_name": "wazuh-dashboard"})).status_code == 200
    refs = (await db_session.execute(select(VaultRef).where(VaultRef.is_active == True))).scalars().all()
    assert [str(r.application_id) for r in refs] == [first]


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token", "auditor_token"])
async def test_non_admins_cannot_manage_or_read(client, db_session, request, token_fixture):
    app_id = await _app(db_session)
    headers = auth_header(request.getfixturevalue(token_fixture))
    assert (await client.put(url(app_id), headers=headers, json={"secret_name": "wazuh-dashboard"})).status_code == 403
    assert (await client.get(url(app_id), headers=headers)).status_code == 403
    assert (await client.delete(url(app_id), headers=headers)).status_code == 403
    assert (await client.post(url(app_id) + "/check", headers=headers)).status_code == 403


async def test_unauthenticated_and_unknown_application(client, db_session, admin_token):
    app_id = await _app(db_session)
    assert (await client.get(url(app_id))).status_code == 401
    r = await client.put(url("00000000-0000-0000-0000-000000000000"), headers=auth_header(admin_token),
                         json={"secret_name": "wazuh-dashboard"})
    assert r.status_code == 404


async def test_check_reports_not_found_without_reading_or_leaking(client, db_session, admin_token):
    """Mock provider holds nothing for the path: the check says so; nothing secret in response/audit."""
    app_id = await _app(db_session)
    r = await client.post(url(app_id) + "/check", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == "no_reference"
    await client.put(url(app_id), headers=auth_header(admin_token), json={"secret_name": "wazuh-dashboard"})
    r = await client.post(url(app_id) + "/check", headers=auth_header(admin_token))
    assert r.json()["status"] == "secret_not_found"


@pytest.mark.parametrize("exc_name, expected", [
    ("SecretProviderUnavailableError", "unavailable"),   # OpenBao down, TLS failure
    ("SecretAccessDeniedError", "access_denied"),         # 403: token revoked/expired/policy
])
async def test_check_fails_closed_when_openbao_is_unavailable_or_denies(client, db_session, admin_token,
                                                                        monkeypatch, exc_name, expected):
    import app.secret_providers as sp

    class Failing:
        async def read_secret(self, path, version=None):
            raise getattr(sp, exc_name)("redacted")

    monkeypatch.setattr(sp, "get_secret_provider", lambda: Failing())
    app_id = await _app(db_session)
    await client.put(url(app_id), headers=auth_header(admin_token), json={"secret_name": "wazuh-dashboard"})
    r = await client.post(url(app_id) + "/check", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == expected
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_REF_CHECKED"))).scalar_one()
    assert audit.result == "FAILURE" and audit.details["result"] == expected


async def test_ok_check_never_returns_or_audits_the_secret(client, db_session, admin_token, monkeypatch):
    import app.secret_providers as sp
    from app.secret_providers import MockSecretProvider

    provider = MockSecretProvider({"securepam/assets/wazuh-dashboard": {"username": "u", "password": PASSWORD}})
    monkeypatch.setattr(sp, "get_secret_provider", lambda: provider)
    app_id = await _app(db_session)
    await client.put(url(app_id), headers=auth_header(admin_token), json={"secret_name": "wazuh-dashboard"})
    r = await client.post(url(app_id) + "/check", headers=auth_header(admin_token))
    assert r.json()["status"] == "ok" and PASSWORD not in r.text
    for path in (url(app_id), f"/api/v1/applications/{app_id}", "/api/v1/audit/"):
        assert PASSWORD not in (await client.get(path, headers=auth_header(admin_token))).text, path
    rows = (await db_session.execute(select(AuditLog))).scalars().all()
    assert all(PASSWORD not in str(row.details) for row in rows)


async def test_deactivate(client, db_session, admin_token):
    app_id = await _app(db_session)
    await client.put(url(app_id), headers=auth_header(admin_token), json={"secret_name": "wazuh-dashboard"})
    assert (await client.delete(url(app_id), headers=auth_header(admin_token))).status_code == 204
    assert (await client.get(url(app_id), headers=auth_header(admin_token))).status_code == 404


def test_allowlist_matches_the_openbao_policies():
    """The API allowlist must stay inside the exact paths the reader AND writer policies grant."""
    from app.core.config import settings
    from scripts.openbao_aws_provision import APP_POLICY_FILE, WRITER_POLICY_FILE
    from scripts.verify_openbao_token import required_data_paths

    reader = set(required_data_paths(APP_POLICY_FILE.read_text()))
    writer = set(required_data_paths(WRITER_POLICY_FILE.read_text()))
    for name in settings.APPLICATION_CREDENTIAL_SECRET_NAMES:
        assert f"securepam/assets/{name}" in reader & writer
