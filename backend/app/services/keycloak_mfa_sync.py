
import hashlib
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit import AuditLog


async def sync_keycloak_mfa_failures(
    db: AsyncSession,
    lookback_hours: int = 24,
) -> int:
    """Import identifiable failed OTP events from Keycloak."""
    client_id = os.getenv("KEYCLOAK_AUDIT_CLIENT_ID")
    client_secret = os.getenv("KEYCLOAK_AUDIT_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise RuntimeError("Keycloak audit-reader credentials are not configured")

    base_url = (
        settings.KEYCLOAK_INTERNAL_URL or settings.KEYCLOAK_URL
    ).rstrip("/")
    realm = settings.KEYCLOAK_REALM
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    imported = 0
    user_cache: dict[str, str | None] = {}

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_response = await client.post(
            f"{base_url}/realms/{realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        token_response.raise_for_status()
        token = token_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        for offset in range(0, 1000, 100):
            response = await client.get(
                f"{base_url}/admin/realms/{realm}/events",
                headers=headers,
                params={
                    "type": "LOGIN_ERROR",
                    "dateFrom": cutoff.strftime("%Y-%m-%d"),
                    "first": offset,
                    "max": 100,
                },
            )
            response.raise_for_status()
            events = response.json()

            if not events:
                break

            for event in events:
                details = event.get("details") or {}

                # Distinguish OTP-form failures from ordinary password
                # failures for the tested Keycloak authentication flow.
                if (
                    event.get("error") != "invalid_user_credentials"
                    or not details.get("selected_credential_id")
                ):
                    continue

                try:
                    event_time = datetime.fromtimestamp(
                        int(event["time"]) / 1000,
                        tz=timezone.utc,
                    )
                except (KeyError, TypeError, ValueError, OverflowError):
                    continue

                if event_time < cutoff:
                    continue

                stable_source_id = str(
                    event.get("id")
                    or "|".join(
                        str(value)
                        for value in (
                            event.get("realmId"),
                            event.get("time"),
                            event.get("userId"),
                            event.get("ipAddress"),
                            event.get("clientId"),
                            details.get("selected_credential_id"),
                        )
                    )
                )
                audit_id = "kc-" + hashlib.sha256(
                    stable_source_id.encode("utf-8")
                ).hexdigest()[:27]

                existing = await db.scalar(
                    select(AuditLog.event_id).where(
                        AuditLog.event_id == audit_id
                    )
                )
                if existing:
                    continue

                # Prefer the username included in the event. If absent,
                # resolve the Keycloak user ID using the audit-reader account.
                username = details.get("username")
                user_id = event.get("userId")

                if not username and user_id:
                    if user_id not in user_cache:
                        try:
                            user_response = await client.get(
                                f"{base_url}/admin/realms/{realm}/users/{user_id}",
                                headers=headers,
                            )

                            if user_response.status_code == 200:
                                user_cache[user_id] = (
                                    user_response.json().get("username")
                                )
                            else:
                                user_cache[user_id] = None
                        except httpx.HTTPError:
                            user_cache[user_id] = None

                    username = user_cache[user_id]

                if not username:
                    username = "Keycloak user (username unavailable)"

                db.add(
                    AuditLog(
                        event_id=audit_id,
                        timestamp=event_time,
                        actor_id=None,
                        actor_username=username,
                        action="MFA_FAILURE",
                        target_type="user",
                        target_id=user_id,
                        source_ip=event.get("ipAddress"),
                        result="FAILURE",
                        severity="WARNING",
                        details={
                            "source": "keycloak",
                            "keycloak_event_type": event.get("type"),
                            "keycloak_error": event.get("error"),
                            "client_id": event.get("clientId"),
                            "auth_method": details.get("auth_method"),
                            "credential_id_present": True,
                        },
                    )
                )
                imported += 1

            if len(events) < 100:
                break

    await db.commit()
    return imported
