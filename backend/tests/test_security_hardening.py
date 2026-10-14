"""
Security hardening regressions:
- DEV_MODE (dev login, HS256 DevAuth, seeded known-password accounts) and a
  placeholder SECRET_KEY are refused outside development/test;
- a JIT grant that is revoked or expires ends the live sessions it authorized;
- unauthenticated health endpoints don't leak dependency error text.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import select

from app.core.config import Settings, SettingsError, settings
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.secret_providers import MockSecretProvider
from app.services.credential_service import CredentialAccessDenied, CredentialService
from app.services.jit_service import JITService
from tests.conftest import auth_header
from tests.test_credential_service import PASSWORD, PATH, _scenario

STRONG_KEY = "k" * 48


def make(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


# --- configuration ----------------------------------------------------------

@pytest.mark.parametrize("environment", ["production", "staging", "prod", "qa"])
def test_dev_mode_refused_outside_development_and_test(environment):
    with pytest.raises(SettingsError, match="DEV_MODE=true is only allowed"):
        make(ENVIRONMENT=environment, DEV_MODE=True, SECRET_KEY=STRONG_KEY, SECRET_PROVIDER="mock")


def test_default_settings_are_not_deployable_as_production():
    """Forgetting DEV_MODE and SECRET_KEY must not yield a running prod app."""
    with pytest.raises(SettingsError) as exc:
        make(ENVIRONMENT="production")
    message = str(exc.value)
    assert "DEV_MODE=true is only allowed" in message
    assert "SECRET_KEY must be changed" in message


@pytest.mark.parametrize("key", ["change-this-to-a-secure-random-string-in-production", "short-key"])
def test_production_rejects_placeholder_or_short_secret_key(key):
    with pytest.raises(SettingsError, match="SECRET_KEY must be changed"):
        make(ENVIRONMENT="production", DEV_MODE=False, SECRET_KEY=key,
             SECRET_PROVIDER="openbao", OPENBAO_ADDR="https://bao:8200", OPENBAO_TOKEN="t")


def test_valid_production_settings_accepted():
    s = make(ENVIRONMENT="production", DEV_MODE=False, SECRET_KEY=STRONG_KEY,
             SECRET_PROVIDER="openbao", OPENBAO_ADDR="https://bao:8200", OPENBAO_TOKEN="t")
    assert s.DEV_MODE is False


@pytest.mark.parametrize("environment", ["development", "test", "Development"])
def test_dev_mode_still_allowed_locally(environment):
    assert make(ENVIRONMENT=environment, DEV_MODE=True).DEV_MODE is True


def test_secret_key_never_echoed_in_error():
    with pytest.raises(SettingsError) as exc:
        make(ENVIRONMENT="production", DEV_MODE=False, SECRET_KEY="leaky-canary-key")
    assert "leaky-canary-key" not in str(exc.value)


# --- JIT grant end -> sessions end --------------------------------------------

async def _live_session(db, req, status="ACTIVE", with_recording=False) -> Session:
    s = Session(session_number=f"SES-{uuid.uuid4().hex[:6].upper()}", user_id=req.user_id, asset_id=req.asset_id,
                request_id=req.access_request_id, jit_grant_id=req.jit_grant_id, protocol="SSH", status=status)
    db.add(s)
    await db.flush()
    if with_recording:
        rec = Recording(session_id=s.id, recording_type="VIDEO", status="RECORDING")
        db.add(rec)
        await db.flush()
        s.recording_id = rec.id
    await db.commit()
    return s


@pytest.mark.parametrize("action, reason", [("revoke", "JIT_REVOKED"), ("expire", "JIT_EXPIRED")])
async def test_ending_grant_ends_its_live_sessions(db_session, action, reason):
    req = await _scenario(db_session)
    live = await _live_session(db_session, req, with_recording=True)
    starting = await _live_session(db_session, req, status="STARTING")
    finished = await _live_session(db_session, req, status="COMPLETED")

    grant = await db_session.get(JITGrant, req.jit_grant_id)
    await getattr(JITService(), action)(db_session, grant)
    await db_session.commit()

    for s in (live, starting, finished):
        await db_session.refresh(s)
    assert live.status == "EXPIRED" and live.end_time is not None
    assert starting.status == "EXPIRED"
    assert finished.status == "COMPLETED"  # already-ended sessions untouched

    # The recording is NOT declared complete by the grant ending: only the gateway that holds the
    # recorder can close and hash the artifact, so it is left for the gateway (or the reconciler).
    rec = await db_session.get(Recording, live.recording_id)
    await db_session.refresh(rec)
    assert rec.status == "RECORDING"

    events = (await db_session.execute(
        select(SessionEvent).where(SessionEvent.event_type == "SESSION_ENDED_BY_GRANT")
    )).scalars().all()
    assert {e.session_id for e in events} == {live.id, starting.id}
    assert all(e.details["reason"] == reason for e in events)


async def test_lazy_expiry_in_validate_ends_sessions(db_session):
    req = await _scenario(db_session, expires_in_minutes=-1)
    live = await _live_session(db_session, req)
    assert await JITService().validate(db_session, user_id=req.user_id, target_id=req.asset_id, protocol="SSH") is None
    await db_session.commit()
    await db_session.refresh(live)
    assert live.status == "EXPIRED"


async def test_other_grants_sessions_unaffected(db_session):
    a = await _scenario(db_session)
    b = await _scenario(db_session, with_ref=False)
    s_a = await _live_session(db_session, a)
    s_b = await _live_session(db_session, b)
    await JITService().revoke(db_session, await db_session.get(JITGrant, a.jit_grant_id))
    await db_session.commit()
    await db_session.refresh(s_a)
    await db_session.refresh(s_b)
    assert (s_a.status, s_b.status) == ("EXPIRED", "ACTIVE")


async def test_revoked_grant_session_cannot_check_out_credentials(db_session):
    req = await _scenario(db_session)
    s = await _live_session(db_session, req)
    await JITService().revoke(db_session, await db_session.get(JITGrant, req.jit_grant_id))
    await db_session.commit()
    provider = MockSecretProvider({PATH: {"password": PASSWORD}})
    with pytest.raises(CredentialAccessDenied):
        async with CredentialService(provider=provider).checkout(db_session, replace(req, session_id=s.id)):
            pass
    assert provider.reads == []


# --- health detail sanitization ----------------------------------------------

async def test_health_does_not_leak_dependency_errors(client, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "REDIS_URL", "redis://leaky-internal-host.invalid:6399/0")
    r = await client.get("/health/detailed", headers=auth_header(admin_token))
    redis = next(s for s in r.json()["services"] if s["service"] == "redis")
    assert redis["status"] == "unhealthy"
    assert redis["details"] == "redis unreachable"
    assert "leaky-internal-host" not in r.text


# --- recording finalization after a session ends without its gateway ----------

async def test_reconciler_fails_unfinalized_recordings_after_grace_and_never_completes(db_session):
    from datetime import timedelta
    from app.models.audit import AuditLog
    from app.services.recording_reconciler import GRACE_SECONDS, reconcile_stale_recordings

    req = await _scenario(db_session)
    orphan = await _live_session(db_session, req, with_recording=True)        # gateway never finalizes
    finalized = await _live_session(db_session, req, with_recording=True)     # gateway finalized in time
    pending = await _live_session(db_session, req, status="STARTING")
    rec_pending = Recording(session_id=pending.id, recording_type="VIDEO", status="PENDING")
    db_session.add(rec_pending)
    await db_session.flush()
    pending.recording_id = rec_pending.id
    await db_session.commit()

    grant = await db_session.get(JITGrant, req.jit_grant_id)
    await JITService().revoke(db_session, grant)
    await db_session.commit()
    rec_fin = await db_session.get(Recording, finalized.recording_id)
    rec_fin.status, rec_fin.file_hash = "COMPLETED", "a" * 64
    await db_session.commit()

    # Inside the grace window nothing is decided (a gateway may still be finalizing).
    assert await reconcile_stale_recordings(db_session) == []
    await db_session.refresh(orphan)
    later = orphan.end_time + timedelta(seconds=GRACE_SECONDS + 1)
    failed = await reconcile_stale_recordings(db_session, now=later)
    assert set(failed) == {str(orphan.recording_id)}  # PENDING of a never-connected session was failed at once

    for rid, want in ((orphan.recording_id, "FAILED"), (finalized.recording_id, "COMPLETED"),
                      (rec_pending.id, "FAILED")):
        r = await db_session.get(Recording, rid)
        await db_session.refresh(r)
        assert r.status == want
    audits = (await db_session.execute(select(AuditLog).where(AuditLog.action == "RECORDING_FAILED"))).scalars().all()
    assert [a.details["reason"] for a in audits] == ["RECORDING_NOT_FINALIZED"]
    assert await reconcile_stale_recordings(db_session, now=later) == []  # idempotent
