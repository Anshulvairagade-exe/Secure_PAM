"""
Import failed-OTP events from Keycloak into SecurePAM's audit log (security events + dashboard metric).

The securepam-otp-audit event listener only LOGS `SECUREPAM_MFA_FAILURE` inside Keycloak; it never
posts to the backend. This module independently reads Keycloak's PERSISTED events through the Admin
REST API with the `securepam-audit-reader` service account (realm-management/view-events only),
keeps exactly the listener's semantics (LOGIN_ERROR + invalid_user_credentials + a selected OTP
credential), deduplicates, and writes one MFA_FAILURE audit row per Keycloak event.

`stats` (optional) receives traceable counts, so "HTTP 200 but nothing imported" is distinguishable
from "nothing matched" and from "already imported".
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit import AuditLog

PAGE_SIZE = 100
MAX_EVENTS = 1000


def _credentials() -> tuple[str, str]:
    client_id = settings.KEYCLOAK_AUDIT_CLIENT_ID or os.getenv("KEYCLOAK_AUDIT_CLIENT_ID", "")
    client_secret = settings.KEYCLOAK_AUDIT_CLIENT_SECRET.get_secret_value() or \
        os.getenv("KEYCLOAK_AUDIT_CLIENT_SECRET", "")
    return client_id, client_secret


def is_otp_failure(event: dict) -> bool:
    """The listener's exact rule (SecurePamOtpEventListenerProvider): a wrong password has no
    selected credential; a wrong OTP code does."""
    details = event.get("details") or {}
    return (
        event.get("type") == "LOGIN_ERROR"
        and event.get("error") == "invalid_user_credentials"
        and bool(str(details.get("selected_credential_id") or "").strip())
    )


def audit_event_id(event: dict) -> str:
    details = event.get("details") or {}
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
    return "kc-" + hashlib.sha256(stable_source_id.encode("utf-8")).hexdigest()[:27]


async def sync_keycloak_mfa_failures(
    db: AsyncSession,
    lookback_hours: int = 24,
    stats: Optional[dict] = None,
) -> int:
    """Import identifiable failed OTP events from Keycloak. Returns the number newly imported."""
    client_id, client_secret = _credentials()
    if not client_id or not client_secret:
        raise RuntimeError("Keycloak audit-reader credentials are not configured")

    counts = {"fetched": 0, "otp_failures": 0, "outside_lookback": 0, "already_imported": 0, "imported": 0}
    base_url = (settings.KEYCLOAK_INTERNAL_URL or settings.KEYCLOAK_URL).rstrip("/")
    realm = settings.KEYCLOAK_REALM
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    user_cache: dict[str, Optional[str]] = {}
    seen: set[str] = set()
    new_rows: list[AuditLog] = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_response = await client.post(
            f"{base_url}/realms/{realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        if token_response.status_code in (400, 401):
            raise RuntimeError(f"KEYCLOAK_AUDIT_READER_AUTH_FAILED (HTTP {token_response.status_code})")
        token_response.raise_for_status()
        headers = {"Authorization": f"Bearer {token_response.json()['access_token']}"}

        for offset in range(0, MAX_EVENTS, PAGE_SIZE):
            response = await client.get(
                f"{base_url}/admin/realms/{realm}/events",
                headers=headers,
                params={
                    "type": "LOGIN_ERROR",
                    # Day granularity on Keycloak's side; the exact cutoff is applied below.
                    "dateFrom": cutoff.strftime("%Y-%m-%d"),
                    "first": offset,
                    "max": PAGE_SIZE,
                },
            )
            if response.status_code == 403:
                raise RuntimeError("KEYCLOAK_EVENTS_FORBIDDEN: the audit-reader service account needs "
                                   "realm-management/view-events")
            response.raise_for_status()
            events = response.json()
            if not events:
                break
            counts["fetched"] += len(events)

            for event in events:
                if not is_otp_failure(event):
                    continue
                counts["otp_failures"] += 1
                details = event.get("details") or {}
                try:
                    event_time = datetime.fromtimestamp(int(event["time"]) / 1000, tz=timezone.utc)
                except (KeyError, TypeError, ValueError, OverflowError):
                    continue
                if event_time < cutoff:
                    counts["outside_lookback"] += 1
                    continue

                audit_id = audit_event_id(event)
                if audit_id in seen or await db.scalar(
                    select(AuditLog.event_id).where(AuditLog.event_id == audit_id)
                ):
                    counts["already_imported"] += 1
                    continue
                seen.add(audit_id)

                # Prefer the username in the event; otherwise resolve the user ID (needs view-users,
                # which the reader deliberately lacks by default: then the name stays unavailable).
                username = details.get("username")
                user_id = event.get("userId")
                if not username and user_id:
                    if user_id not in user_cache:
                        try:
                            user_response = await client.get(
                                f"{base_url}/admin/realms/{realm}/users/{user_id}", headers=headers
                            )
                            user_cache[user_id] = (
                                user_response.json().get("username") if user_response.status_code == 200 else None
                            )
                        except httpx.HTTPError:
                            user_cache[user_id] = None
                    username = user_cache[user_id]
                if not username:
                    username = "Keycloak user (username unavailable)"

                row = AuditLog(
                    event_id=audit_id,
                    timestamp=event_time,
                    actor_id=None,
                    actor_username=username,
                    action="MFA_FAILURE",
                    target_type="user",
                    target_id=user_id,
                    source_ip=event.get("ipAddress"),
                    result="FAILURE",
                    severity="MEDIUM",
                    details={
                        "source": "keycloak",
                        "keycloak_event_type": event.get("type"),
                        "keycloak_error": event.get("error"),
                        "client_id": event.get("clientId"),
                        "auth_method": details.get("auth_method"),
                        # No "credential"/"otp" in the key: the SIEM redactor masks such keys.
                        "second_factor_failure": True,
                    },
                )
                db.add(row)
                new_rows.append(row)

            if len(events) < PAGE_SIZE:
                break

    await db.commit()
    counts["imported"] = len(new_rows)

    from app.core.siem import emit  # same secret-free sink every other audit event goes to
    for row in new_rows:
        emit({"event_id": row.event_id, "timestamp": row.timestamp.isoformat(), "action": row.action,
              "result": row.result, "severity": row.severity, "actor": row.actor_username,
              "target_type": row.target_type, "target_id": row.target_id, "session_id": None,
              "request_id": None, "source_ip": row.source_ip, "details": row.details})

    if stats is not None:
        stats.update(counts)
    return counts["imported"]
