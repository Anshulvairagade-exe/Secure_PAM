
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.services.keycloak_mfa_sync import sync_keycloak_mfa_failures


def make_event(
    event_id: str,
    *,
    minutes_ago: int = 5,
    error: str = "invalid_user_credentials",
    selected_credential_id: str | None = "otp-credential",
    username: str | None = None,
) -> dict:
    timestamp = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    details = {}
    if selected_credential_id:
        details["selected_credential_id"] = selected_credential_id
    if username:
        details["username"] = username

    return {
        "id": event_id,
        "time": int(timestamp.timestamp() * 1000),
        "type": "LOGIN_ERROR",
        "realmId": "test-realm",
        "clientId": "securepam-app",
        "userId": "test-user-id",
        "ipAddress": "192.0.2.10",
        "error": error,
        "details": details,
    }


def mock_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


@pytest.mark.asyncio
async def test_imports_otp_failure_and_uses_username_fallback(
    db_session, monkeypatch
):
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "test-secret")

    otp_event = make_event("otp-event-1")

    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "fake-token"})
    client.get.return_value = mock_response([otp_event])

    with patch(
        "app.services.keycloak_mfa_sync.httpx.AsyncClient"
    ) as client_factory:
        client_factory.return_value.__aenter__.return_value = client

        imported = await sync_keycloak_mfa_failures(
            db_session, lookback_hours=1
        )

    assert imported == 1

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "MFA_FAILURE")
    )
    record = result.scalar_one()

    assert record.event_id.startswith("kc-")
    assert record.actor_username == "Keycloak user (username unavailable)"
    assert record.details["source"] == "keycloak"
    assert record.details["second_factor_failure"] is True
    assert record.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_excludes_wrong_password_and_unknown_user(
    db_session, monkeypatch
):
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "test-secret")

    events = [
        make_event(
            "password-failure",
            selected_credential_id=None,
            username="auditor",
        ),
        make_event(
            "unknown-user",
            error="user_not_found",
            selected_credential_id=None,
            username="unknown",
        ),
    ]

    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "fake-token"})
    client.get.return_value = mock_response(events)

    with patch(
        "app.services.keycloak_mfa_sync.httpx.AsyncClient"
    ) as client_factory:
        client_factory.return_value.__aenter__.return_value = client

        imported = await sync_keycloak_mfa_failures(
            db_session, lookback_hours=1
        )

    assert imported == 0

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "MFA_FAILURE")
    )
    assert result.scalars().all() == []


@pytest.mark.asyncio
async def test_repeat_import_does_not_duplicate_event(
    db_session, monkeypatch
):
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "test-secret")

    otp_event = make_event("otp-event-repeat")

    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "fake-token"})
    client.get.return_value = mock_response([otp_event])

    with patch(
        "app.services.keycloak_mfa_sync.httpx.AsyncClient"
    ) as client_factory:
        client_factory.return_value.__aenter__.return_value = client

        first_count = await sync_keycloak_mfa_failures(
            db_session, lookback_hours=1
        )
        second_count = await sync_keycloak_mfa_failures(
            db_session, lookback_hours=1
        )

    assert first_count == 1
    assert second_count == 0

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "MFA_FAILURE")
    )
    assert len(result.scalars().all()) == 1


@pytest.mark.asyncio
async def test_settings_credentials_and_traceable_stats(db_session, monkeypatch):
    """A host-run backend loads .env through settings (not os.environ): that path must work, and
    the counts must explain a zero import."""
    from pydantic import SecretStr
    from app.core.config import settings

    monkeypatch.delenv("KEYCLOAK_AUDIT_CLIENT_ID", raising=False)
    monkeypatch.delenv("KEYCLOAK_AUDIT_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(settings, "KEYCLOAK_AUDIT_CLIENT_ID", "securepam-audit-reader")
    monkeypatch.setattr(settings, "KEYCLOAK_AUDIT_CLIENT_SECRET", SecretStr("from-settings"))
    events = [make_event("dup-1"), make_event("dup-1"), make_event("pw", selected_credential_id=None),
              make_event("old", minutes_ago=180)]
    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "fake-token"})
    client.get.return_value = mock_response(events)
    stats: dict = {}
    with patch("app.services.keycloak_mfa_sync.httpx.AsyncClient") as factory:
        factory.return_value.__aenter__.return_value = client
        imported = await sync_keycloak_mfa_failures(db_session, lookback_hours=1, stats=stats)
    assert imported == 1  # the same event twice in one response is imported once
    assert stats == {"fetched": 4, "otp_failures": 3, "outside_lookback": 1, "already_imported": 1, "imported": 1}
    assert client.post.call_args.kwargs["data"]["client_secret"] == "from-settings"


@pytest.mark.asyncio
async def test_forbidden_events_endpoint_is_reported_precisely(db_session, monkeypatch):
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "test-secret")
    forbidden = MagicMock(status_code=403)
    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "fake-token"})
    client.get.return_value = forbidden
    with patch("app.services.keycloak_mfa_sync.httpx.AsyncClient") as factory:
        factory.return_value.__aenter__.return_value = client
        with pytest.raises(RuntimeError, match="view-events"):
            await sync_keycloak_mfa_failures(db_session, lookback_hours=1)


@pytest.mark.asyncio
async def test_imported_events_reach_the_siem_sink_without_secrets(db_session, monkeypatch, tmp_path):
    import json
    from app.core.config import settings

    sink = tmp_path / "siem.jsonl"
    monkeypatch.setattr(settings, "SIEM_EVENT_LOG_PATH", str(sink))
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "test-secret-canary")
    client = AsyncMock()
    client.post.return_value = mock_response({"access_token": "token-canary"})
    client.get.return_value = mock_response([make_event("siem-1", username="alice")])
    with patch("app.services.keycloak_mfa_sync.httpx.AsyncClient") as factory:
        factory.return_value.__aenter__.return_value = client
        assert await sync_keycloak_mfa_failures(db_session, lookback_hours=1) == 1
    line = json.loads(sink.read_text().strip())["securepam"]
    assert line["action"] == "MFA_FAILURE" and line["actor"] == "alice" and line["details"]["second_factor_failure"] is True
    assert "canary" not in sink.read_text()


def test_audit_reader_secret_can_come_from_a_protected_file(tmp_path):
    """Container/ECS delivery: KEYCLOAK_AUDIT_CLIENT_SECRET_FILE (0600). Group/world-readable is refused."""
    import os
    from app.core.config import Settings, SettingsError

    f = tmp_path / "reader.secret"
    f.write_text("file-secret-canary\n")
    os.chmod(f, 0o600)
    s = Settings(_env_file=None, KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=str(f))
    assert s.KEYCLOAK_AUDIT_CLIENT_SECRET.get_secret_value() == "file-secret-canary"
    assert "file-secret-canary" not in repr(s)
    # an explicit environment value wins over the file
    assert Settings(_env_file=None, KEYCLOAK_AUDIT_CLIENT_SECRET="env-value",
                    KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=str(f)).KEYCLOAK_AUDIT_CLIENT_SECRET.get_secret_value() == "env-value"
    os.chmod(f, 0o644)
    with pytest.raises(SettingsError, match="chmod 600") as exc:
        Settings(_env_file=None, KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=str(f))
    assert "file-secret-canary" not in str(exc.value)
    with pytest.raises(SettingsError, match="cannot be read"):
        Settings(_env_file=None, KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=str(tmp_path / "missing"))
