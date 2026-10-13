"""
Credential checkout failures surface as precise, safe errors, and the
credential-reference check reports them before an operator hits them.

Covers: missing provider configuration, OpenBao permission denial, missing
credential reference, missing secret, unreachable target, and successful
retrieval. No response or log line may contain the secret.
"""

import json
import socket
import uuid

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.core.config import Settings, SettingsError, settings
from app.main import app
from app.models.asset import Asset
from app.models.session import Session
from app.api.v1.ssh_sessions import get_credential_service
from app.secret_providers import (
    MockSecretProvider,
    SecretAccessDeniedError,
    SecretProviderConfigError,
    SecretProviderUnavailableError,
)
from app.services.credential_service import CredentialService
from app.services.ssh_host_key import SSHHostKeyValidator
from app.services.ssh_terminal_gateway import AsyncSSHTerminalGateway, get_terminal_gateway
from tests.conftest import auth_header
from tests.test_ssh_session_endpoints import CANARY, SSH_PATH, _launch_body, _ssh_ready


class RaisingProvider(MockSecretProvider):
    """A provider whose reads fail the way OpenBao can fail."""

    def __init__(self, exc):
        super().__init__({})
        self._exc = exc

    async def read_secret(self, path, *, version=None):
        raise self._exc


@pytest.fixture(autouse=True)
def _recording_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(tmp_path / "recordings"))


def _use_provider(provider):
    app.dependency_overrides[get_credential_service] = lambda: CredentialService(provider=provider)


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.pop(get_credential_service, None)
    app.dependency_overrides.pop(get_terminal_gateway, None)


async def _launch(client, token, req):
    return await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(token), json=_launch_body(req))


# --- launch errors -------------------------------------------------------------

@pytest.mark.parametrize("exc, status_code, text", [
    (SecretProviderConfigError("bad"), 503, "not configured correctly"),
    (SecretAccessDeniedError("denied (HTTP 403)"), 503, "not permitted to read"),
    (SecretProviderUnavailableError("down"), 503, "unreachable"),
])
async def test_provider_failures_are_specific(client: AsyncClient, db_session, operator_token, exc, status_code, text):
    _use_provider(RaisingProvider(exc))
    req = await _ssh_ready(db_session)
    r = await _launch(client, operator_token, req)
    assert r.status_code == status_code and text in r.json()["detail"]
    assert "Credential provider unavailable" not in r.text


async def test_missing_secret_says_so_and_session_records_why(client: AsyncClient, db_session, operator_token):
    _use_provider(MockSecretProvider({}))  # reference exists, secret does not
    req = await _ssh_ready(db_session)
    r = await _launch(client, operator_token, req)
    assert r.status_code == 409
    assert "points to a secret that does not exist" in r.json()["detail"]

    sessions = (await client.get("/api/v1/sessions/", headers=auth_header(operator_token))).json()["items"]
    failed = next(s for s in sessions if s["status"] == "FAILED")
    assert failed["failure_reason"] == "SECRET_NOT_FOUND"
    assert "does not exist" in failed["failure_message"]


async def test_missing_credential_reference_is_a_configuration_error(client: AsyncClient, db_session, operator_token):
    _use_provider(MockSecretProvider({SSH_PATH: {"password": CANARY}}))
    req = await _ssh_ready(db_session, with_ref=False)
    r = await _launch(client, operator_token, req)
    assert r.status_code == 409
    assert "No credential is configured for this target" in r.json()["detail"]


async def test_malformed_secret_is_reported(client: AsyncClient, db_session, operator_token):
    _use_provider(MockSecretProvider({SSH_PATH: {"username": "ubuntu"}}))  # no password field
    req = await _ssh_ready(db_session)
    r = await _launch(client, operator_token, req)
    assert r.status_code == 409 and "not in the expected format" in r.json()["detail"]


async def test_successful_retrieval_prepares_but_does_not_activate(client: AsyncClient, db_session, operator_token):
    _use_provider(MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}}))
    req = await _ssh_ready(db_session)
    r = await _launch(client, operator_token, req)
    assert r.status_code == 201 and CANARY not in r.text
    s = await db_session.get(Session, uuid.UUID(r.json()["session_id"]))
    assert s.status == "STARTING" and s.start_time is None  # ACTIVE only once the SSH connection exists


def test_missing_provider_configuration_fails_at_startup():
    with pytest.raises(SettingsError, match="OPENBAO_TOKEN is required"):
        Settings(_env_file=None, SECRET_PROVIDER="openbao", OPENBAO_ADDR="http://127.0.0.1:8200")


# --- unreachable target ----------------------------------------------------------

async def test_unreachable_target_fails_with_specific_message(db_session, operator_token):
    _use_provider(MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}}))
    with socket.socket() as probe:  # a local port with nothing listening
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    req = await _ssh_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.hostname, asset.ip_address, asset.port = "127.0.0.1", "127.0.0.1", closed_port
    await db_session.commit()
    gateway = AsyncSSHTerminalGateway(
        host_key_validator=SSHHostKeyValidator(known_hosts_data=f"127.0.0.1 ssh-ed25519 {'A' * 68}\n"),
        connect_timeout=3,
    )
    app.dependency_overrides[get_terminal_gateway] = lambda: gateway

    client = TestClient(app)
    data = client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token), json=_launch_body(req)).json()
    with client.websocket_connect(f"/api/v1/sessions/ssh/{data['session_id']}/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": data["ticket"]}))
        frame = json.loads(ws.receive_text())
    assert frame["type"] == "error"
    assert "could not be reached" in frame["message"] or "host key" in frame["message"]
    await db_session.refresh(await db_session.get(Session, uuid.UUID(data["session_id"])))
    s = await db_session.get(Session, uuid.UUID(data["session_id"]))
    assert s.status == "FAILED" and s.start_time is None
    assert gateway.get_live_connection(s.id) is None


# --- credential reference check ----------------------------------------------------

async def _asset_with_ref(client, admin_token, db_session):
    req = await _ssh_ready(db_session)
    return str(req.asset_id)


@pytest.mark.parametrize("provider, expected", [
    (MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}}), "ok"),
    (MockSecretProvider({}), "secret_not_found"),
    (RaisingProvider(SecretAccessDeniedError("denied")), "access_denied"),
    (RaisingProvider(SecretProviderUnavailableError("down")), "unavailable"),
    (MockSecretProvider({SSH_PATH: {"username": "ubuntu"}}), "malformed"),
])
async def test_reference_check_reports_status_without_the_secret(
    client: AsyncClient, admin_token, db_session, monkeypatch, provider, expected
):
    monkeypatch.setattr("app.secret_providers.get_secret_provider", lambda: provider)
    asset_id = await _asset_with_ref(client, admin_token, db_session)
    r = await client.post(f"/api/v1/assets/{asset_id}/credential-ref/check", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == expected
    assert CANARY not in r.text


async def test_reference_check_requires_vault_manage(client: AsyncClient, operator_token, admin_token, db_session):
    asset_id = await _asset_with_ref(client, admin_token, db_session)
    r = await client.post(f"/api/v1/assets/{asset_id}/credential-ref/check", headers=auth_header(operator_token))
    assert r.status_code == 403


# --- grant binding with several live grants for one target ---------------------

async def test_each_request_uses_its_own_grant(client: AsyncClient, db_session, operator_token):
    """Two approved requests for the same target: the older one is still
    launchable, and revoking its grant denies it even though the newer
    grant remains active."""
    from app.models.jit_grant import JITGrant

    _use_provider(MockSecretProvider({SSH_PATH: {"username": "ubuntu", "password": CANARY}}))
    older = await _ssh_ready(db_session)
    newer = await _ssh_ready(db_session, with_ref=False)  # one reference per target
    assert older.asset_id == newer.asset_id and older.jit_grant_id != newer.jit_grant_id

    r = await _launch(client, operator_token, older)
    assert r.status_code == 201, r.text
    s = await db_session.get(Session, uuid.UUID(r.json()["session_id"]))
    assert s.jit_grant_id == older.jit_grant_id

    grant = await db_session.get(JITGrant, older.jit_grant_id)
    grant.status = "REVOKED"
    await db_session.commit()
    denied = await _launch(client, operator_token, older)
    assert denied.status_code == 403
    assert (await _launch(client, operator_token, newer)).status_code == 201
