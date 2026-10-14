"""
Secret providers in isolation — no live OpenBao. OpenBaoSecretProvider is
driven through httpx.MockTransport, so every request it makes (method,
URL, headers) and every response shape is deterministic.
"""

import httpx
import pytest
from pydantic import SecretStr

from app.secret_providers import (
    Credential,
    InvalidSecretReferenceError,
    MalformedSecretError,
    MockSecretProvider,
    OpenBaoSecretProvider,
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretProvider,
    SecretProviderError,
    SecretProviderUnavailableError,
)
from app.secret_providers.paths import asset_secret_path, validate_secret_name, validate_secret_path

TOKEN = "s.TOKENCANARY0123456789"
PASSWORD = "PW-CANARY-not-real"
PATH = "securepam/assets/test-linux-01"


def kv2_body(data=None, version=3, deletion_time="", destroyed=False):
    return {
        "request_id": "x",
        "data": {
            "data": {"username": "fakeuser", "password": PASSWORD} if data is None else data,
            "metadata": {"version": version, "deletion_time": deletion_time, "destroyed": destroyed},
        },
    }


def provider_with(handler) -> tuple[OpenBaoSecretProvider, list]:
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request):
        seen.append(request)
        return handler(request)

    p = OpenBaoSecretProvider(
        addr="http://bao.test:8200", token=SecretStr(TOKEN), mount_point="secret",
        path_prefix="securepam", connect_timeout=1, request_timeout=1,
        transport=httpx.MockTransport(_record),
    )
    return p, seen


# --- path rules ---

@pytest.mark.parametrize("path", [PATH, "securepam/assets/a.b_c-1", "securepam/x"])
def test_valid_paths(path):
    assert validate_secret_path(path, "securepam") == path


@pytest.mark.parametrize(
    "path",
    [
        "", "securepam", "securepam/", "/securepam/x", "securepam//x", "securepam/../sys/x",
        "securepam/assets/..", "other/assets/x", "secret/data/securepam/x", "securepamX/x",
        "securepam/assets/x?version=1", "securepam/assets/x y", "securepam/assets/%2e%2e",
        "securepam/" + "a" * 600,
    ],
)
def test_invalid_paths_rejected(path):
    with pytest.raises(InvalidSecretReferenceError):
        validate_secret_path(path, "securepam")


@pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "", "x" * 200, "a..b"])
def test_invalid_secret_names_rejected(name):
    with pytest.raises(InvalidSecretReferenceError):
        validate_secret_name(name)


def test_asset_secret_path_convention():
    assert asset_secret_path("securepam", "test-linux-01") == PATH


# --- interface is read-only ---

def test_provider_interface_exposes_no_write_operations():
    for cls in (SecretProvider, OpenBaoSecretProvider, MockSecretProvider):
        public = {n for n in dir(cls) if not n.startswith("_")}
        assert public <= {"name", "read_secret", "health"}, public


# --- mock provider ---

async def test_mock_provider_reads_fake_default():
    record = await MockSecretProvider().read_secret(PATH)
    assert record.data["password"] == "mock-password-not-real"


async def test_mock_provider_failures():
    with pytest.raises(SecretNotFoundError):
        await MockSecretProvider().read_secret("securepam/assets/missing")
    with pytest.raises(SecretProviderUnavailableError):
        await MockSecretProvider(available=False).read_secret(PATH)
    with pytest.raises(SecretAccessDeniedError):
        await MockSecretProvider(denied_paths=[PATH]).read_secret(PATH)
    with pytest.raises(InvalidSecretReferenceError):
        await MockSecretProvider().read_secret("../etc/passwd")
    assert (await MockSecretProvider(available=False).health()).healthy is False


# --- OpenBao KV v2 ---

async def test_openbao_kv2_read_parses_data_and_version():
    p, seen = provider_with(lambda r: httpx.Response(200, json=kv2_body()))
    record = await p.read_secret(PATH)

    assert record.data == {"username": "fakeuser", "password": PASSWORD}
    assert record.version == 3
    (req,) = seen
    assert req.method == "GET"
    assert str(req.url) == "http://bao.test:8200/v1/secret/data/securepam/assets/test-linux-01"
    assert req.headers["X-Vault-Token"] == TOKEN
    assert TOKEN not in str(req.url)
    assert PASSWORD not in repr(record)


async def test_openbao_pinned_version_is_sent():
    p, seen = provider_with(lambda r: httpx.Response(200, json=kv2_body(version=2)))
    assert (await p.read_secret(PATH, version=2)).version == 2
    assert seen[0].url.params["version"] == "2"


@pytest.mark.parametrize(
    "status, exc",
    [
        (404, SecretNotFoundError),
        (403, SecretAccessDeniedError),
        (401, SecretAccessDeniedError),
        (429, SecretProviderUnavailableError),
        (500, SecretProviderUnavailableError),
        (503, SecretProviderUnavailableError),
        (400, SecretProviderError),
    ],
)
async def test_openbao_error_statuses(status, exc):
    body = {"errors": [f"permission denied {TOKEN} {PASSWORD}"]}
    p, _ = provider_with(lambda r: httpx.Response(status, json=body))
    with pytest.raises(exc) as info:
        await p.read_secret(PATH)
    # The provider response body never makes it into the exception.
    assert TOKEN not in str(info.value) and PASSWORD not in str(info.value)
    assert info.value.__cause__ is None


@pytest.mark.parametrize(
    "error", [httpx.ConnectError("refused"), httpx.ConnectTimeout("t"), httpx.ReadTimeout("t")]
)
async def test_openbao_unreachable_maps_to_unavailable(error):
    def boom(request):
        raise error

    p, _ = provider_with(boom)
    with pytest.raises(SecretProviderUnavailableError) as info:
        await p.read_secret(PATH)
    assert TOKEN not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"data": "x"}),
        httpx.Response(200, json={"data": {"data": "x", "metadata": {}}}),
    ],
)
async def test_openbao_malformed_responses(response):
    p, _ = provider_with(lambda r: response)
    with pytest.raises(MalformedSecretError):
        await p.read_secret(PATH)


@pytest.mark.parametrize(
    "body",
    [
        kv2_body(data=None, deletion_time="2026-01-01T00:00:00Z"),
        kv2_body(destroyed=True),
        {"data": {"data": None, "metadata": {"version": 1}}},
    ],
)
async def test_openbao_deleted_or_destroyed_is_not_found(body):
    p, _ = provider_with(lambda r: httpx.Response(200, json=body))
    with pytest.raises(SecretNotFoundError):
        await p.read_secret(PATH)


async def test_openbao_rejects_invalid_path_before_any_request():
    p, seen = provider_with(lambda r: httpx.Response(200, json=kv2_body()))
    with pytest.raises(InvalidSecretReferenceError):
        await p.read_secret("../../sys/mounts")
    assert seen == []


async def test_openbao_health_sends_no_token_and_maps_states():
    for status, healthy, text in [(200, True, "unsealed"), (503, False, "sealed"), (429, False, "standby")]:
        p, seen = provider_with(lambda r, s=status: httpx.Response(s, json={}))
        h = await p.health()
        assert (h.healthy, text in h.detail) == (healthy, True)
        assert "X-Vault-Token" not in seen[0].headers
        assert TOKEN not in h.detail

    def boom(request):
        raise httpx.ConnectError("refused")

    p, _ = provider_with(boom)
    assert (await p.health()).healthy is False


def test_openbao_repr_hides_token():
    p, _ = provider_with(lambda r: httpx.Response(200))
    assert TOKEN not in repr(p)


# --- Credential value type ---

def test_credential_redacts_and_wipes():
    import pickle

    c = Credential(username="u", secret=PASSWORD, secret_type="PASSWORD", version=1)
    assert PASSWORD not in repr(c) and PASSWORD not in str(c) and PASSWORD not in f"{c}"
    assert c.reveal() == PASSWORD
    with pytest.raises(TypeError):
        pickle.dumps(c)
    c.wipe()
    assert c.is_wiped
    with pytest.raises(RuntimeError):
        c.reveal()


def test_openbao_health_reports_a_token_fingerprint_never_the_token():
    import asyncio
    import hashlib

    import httpx
    from pydantic import SecretStr

    from app.secret_providers.openbao import OpenBaoSecretProvider

    token = "s.token-canary-not-real-0123456789"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"initialized": True, "sealed": False}))
    provider = OpenBaoSecretProvider(addr="http://127.0.0.1:18200", token=SecretStr(token), mount_point="secret",
                                     path_prefix="securepam", connect_timeout=1, request_timeout=1, transport=transport)
    health = asyncio.run(provider.health())
    assert health.healthy and hashlib.sha256(token.encode()).hexdigest()[:8] in health.detail
    assert token not in health.detail and "canary" not in health.detail
