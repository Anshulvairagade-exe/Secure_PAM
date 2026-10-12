"""OpenBao SecretProvider tests. No live server and no real token."""

import json

import httpx
import pytest

from app.secrets.base import (
    SecretDeniedError,
    SecretMaterial,
    SecretNotFoundError,
    SecretTimeoutError,
    SecretUnauthenticatedError,
    SecretUnavailableError,
)
from app.secrets.openbao import DisabledSecretProvider, OpenBaoSecretProvider, get_secret_provider

SECRET = "synthetic-secret-value"
PRIVATE_KEY = "synthetic-private-key"
TOKEN = "test-runtime-token"
PATH = "secret/targets/lab-sample"


class ListLogger:
    def __init__(self):
        self.records = []

    def info(self, event, **kwargs):
        self.records.append((event, kwargs))

    def warning(self, event, **kwargs):
        self.records.append((event, kwargs))


def _logged_text(logger: ListLogger) -> str:
    return json.dumps(logger.records)


def _provider(handler, logger, token=TOKEN):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return OpenBaoSecretProvider(
        base_url="http://openbao.test",
        token=token,
        mount="secret",
        client=client,
        logger=logger,
    )


def _kv_body():
    return {
        "data": {
            "data": {
                "username": "lab-operator",
                "password": SECRET,
                "private_key": PRIVATE_KEY,
            },
            "metadata": {"version": 1},
        }
    }


async def test_read_kv2_secret_and_keeps_values_out_of_logs():
    logger = ListLogger()
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["token"] = request.headers.get("X-Vault-Token")
        return httpx.Response(200, json=_kv_body())

    material = await _provider(handler, logger).read(PATH)

    assert seen["path"] == "/v1/secret/data/targets/lab-sample"
    assert seen["token"] == TOKEN
    assert material.username == "lab-operator"
    assert material.password == SECRET
    assert SECRET not in repr(material)
    assert PRIVATE_KEY not in repr(material)
    assert SECRET not in _logged_text(logger)
    assert PRIVATE_KEY not in _logged_text(logger)
    assert TOKEN not in _logged_text(logger)
    assert logger.records[-1][0] == "secret_read"


@pytest.mark.parametrize(
    ("status_code", "error_type", "message"),
    [
        (401, SecretUnauthenticatedError, "OpenBao authentication failed"),
        (403, SecretDeniedError, "OpenBao denied access to the secret"),
        (404, SecretNotFoundError, "Secret was not found"),
        (500, SecretUnavailableError, "OpenBao is unavailable"),
    ],
)
async def test_openbao_error_status_hides_response_body(status_code, error_type, message):
    logger = ListLogger()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"errors": [SECRET], "auth": {"client_token": TOKEN}})

    with pytest.raises(error_type) as caught:
        await _provider(handler, logger).read(PATH)

    assert str(caught.value) == message
    assert SECRET not in str(caught.value)
    assert TOKEN not in str(caught.value)
    assert SECRET not in _logged_text(logger)
    assert TOKEN not in _logged_text(logger)


async def test_timeout_does_not_include_exception_text():
    logger = ListLogger()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timed out reading {SECRET}")

    with pytest.raises(SecretTimeoutError) as caught:
        await _provider(handler, logger).read(PATH)

    assert str(caught.value) == "OpenBao request timed out"
    assert SECRET not in str(caught.value)
    assert SECRET not in _logged_text(logger)


async def test_connection_failure_is_unavailable():
    logger = ListLogger()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"connection failed {TOKEN}")

    with pytest.raises(SecretUnavailableError) as caught:
        await _provider(handler, logger).read(PATH)

    assert str(caught.value) == "OpenBao is unavailable"
    assert TOKEN not in str(caught.value)
    assert TOKEN not in _logged_text(logger)


@pytest.mark.parametrize(
    "vault_path",
    [
        "secret/sys/policy",
        "secret/targets/../../sys",
        "secret/targets/lab sample",
        "http://openbao.test/v1/secret/data/targets/lab-sample",
        "",
        "secret/targets",
    ],
)
async def test_rejects_paths_outside_target_and_application_prefixes(vault_path):
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=_kv_body())

    with pytest.raises(SecretDeniedError, match="Invalid secret path"):
        await _provider(handler, ListLogger()).read(vault_path)

    assert called["count"] == 0


async def test_empty_token_fails_before_any_request():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=_kv_body())

    with pytest.raises(SecretUnauthenticatedError):
        await _provider(handler, ListLogger(), token="").read(PATH)

    assert called["count"] == 0


async def test_disabled_provider_refuses_retrieval():
    with pytest.raises(SecretUnavailableError, match="disabled"):
        await DisabledSecretProvider().read(PATH)


def test_factory_stays_disabled_without_a_configured_token(monkeypatch):
    monkeypatch.setattr("app.secrets.openbao.settings.VAULT_ENABLED", True)
    monkeypatch.setattr("app.secrets.openbao.settings.VAULT_TOKEN", "")
    assert isinstance(get_secret_provider(), DisabledSecretProvider)


def test_secret_material_repr_lists_field_names_only():
    material = SecretMaterial(username="lab-operator", password=SECRET, private_key=PRIVATE_KEY)
    assert repr(material) == "SecretMaterial(fields=['username', 'password', 'private_key'])"
    assert SECRET not in repr(material)
