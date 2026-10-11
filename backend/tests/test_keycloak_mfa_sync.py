
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
    assert record.details["credential_id_present"] is True


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
