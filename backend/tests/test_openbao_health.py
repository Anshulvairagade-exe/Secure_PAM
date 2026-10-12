"""OpenBao health probe. The HTTP call is mocked, so no server is required."""

import httpx

from app.api.v1.health import _check_vault
from app.core.config import settings

LEAK = "should-not-leak-from-health-body"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_disabled_vault_stays_local_and_does_not_call_openbao(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", False)
    monkeypatch.setattr(settings, "VAULT_TOKEN", "")
    monkeypatch.setattr(settings, "VAULT_TOKEN_FILE", "")
    monkeypatch.setattr(settings, "DEV_MODE", True)
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(500, text=LEAK)

    result = _check_vault(_client(handler))

    assert called["count"] == 0
    assert result.status == "healthy"
    assert result.details == "DEV_MODE: MockVault active"


def test_enabled_vault_reports_reachable_without_response_body(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", True)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/sys/health"
        return httpx.Response(200, json={"sealed": False, "root_token": LEAK})

    result = _check_vault(_client(handler))

    assert result.status == "healthy"
    assert result.details == "OpenBao reachable"
    assert LEAK not in (result.details or "")


def test_sealed_openbao_is_unhealthy(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"sealed": True, "detail": LEAK})

    result = _check_vault(_client(handler))

    assert result.status == "unhealthy"
    assert result.details == "OpenBao sealed"
    assert LEAK not in (result.details or "")


def test_openbao_timeout_uses_a_fixed_message(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", True)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout(LEAK)

    result = _check_vault(_client(handler))

    assert result.status == "unhealthy"
    assert result.details == "OpenBao request timed out"
    assert LEAK not in (result.details or "")


def test_runtime_token_file_enables_probe_without_enabling_flag(monkeypatch, tmp_path):
    token_file = tmp_path / "app-token"
    token_file.write_text("file-runtime-token\n", encoding="utf-8")
    monkeypatch.setattr(settings, "VAULT_ENABLED", False)
    monkeypatch.setattr(settings, "VAULT_TOKEN", "")
    monkeypatch.setattr(settings, "VAULT_TOKEN_FILE", str(token_file))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"sealed": False})

    result = _check_vault(_client(handler))

    assert result.status == "healthy"
    assert result.details == "OpenBao reachable"
    assert "file-runtime-token" not in (result.details or "")


def test_openbao_connection_error_is_unreachable(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", True)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(LEAK)

    result = _check_vault(_client(handler))

    assert result.status == "unhealthy"
    assert result.details == "OpenBao unreachable"
    assert LEAK not in (result.details or "")
