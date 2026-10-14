"""Admin session control: authorization, termination, grant revocation, honest failures, audit."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.main import app
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.services import session_termination
from app.services.ssh_terminal_gateway import get_terminal_gateway
from tests.conftest import auth_header
from tests.test_ssh_session_endpoints import (  # noqa: F401  (fixtures)
    _actions, _launch_body, _recording_storage, _ssh_ready, provider,
)


@pytest.fixture(autouse=True)
def _fast_settle(monkeypatch):
    monkeypatch.setattr(session_termination, "SETTLE_SECONDS", 0)
    monkeypatch.setattr(session_termination, "GATEWAY_WAIT_SECONDS", 1.0)


async def _get(db, model, pk):
    return await db.get(model, pk, populate_existing=True)


async def _user(db, name):
    return (await db.execute(select(User).where(User.username == name))).scalar_one()


async def _live(db, req, status="ACTIVE", recording=None):
    s = Session(session_number=f"SES-{uuid.uuid4().hex[:6].upper()}", user_id=req.user_id, asset_id=req.asset_id,
                request_id=req.access_request_id, jit_grant_id=req.jit_grant_id, protocol="SSH", status=status,
                start_time=datetime.now(timezone.utc))
    db.add(s)
    await db.flush()
    if recording:
        rec = Recording(session_id=s.id, recording_type="TERMINAL", status=recording, file_path="/nowhere/x.cast")
        db.add(rec)
        await db.flush()
        s.recording_id = rec.id
    await db.commit()
    return s


class FakeGateway:
    """Stands in for the in-process terminal gateway. A held connection is released the way the
    real monitor does it: shortly after the session leaves ACTIVE. `stuck` never releases."""
    def __init__(self, held=(), stuck=False, release_exceptions=()):
        self.held, self.stuck, self.closed, self.never = set(held), stuck, [], set(release_exceptions)
        self._polls = {}

    def get_live_connection(self, sid):
        if sid not in self.held:
            return None
        self._polls[sid] = self._polls.get(sid, 0) + 1
        if not self.stuck and sid not in self.never and self._polls[sid] > 2:
            self.held.discard(sid)
            self.closed.append(sid)
            return None
        return object()


@pytest.fixture
def gateway():
    g = FakeGateway()
    app.dependency_overrides[get_terminal_gateway] = lambda: g
    yield g
    app.dependency_overrides.pop(get_terminal_gateway, None)


# --- authorization ---------------------------------------------------------------

@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token", "auditor_token"])
async def test_non_admins_cannot_view_or_terminate_user_sessions(client, db_session, request, token_fixture, gateway):
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req)
    h = auth_header(request.getfixturevalue(token_fixture))
    uid = req.user_id
    assert (await client.get(f"/api/v1/users/{uid}/sessions", headers=h)).status_code == 403
    assert (await client.post(f"/api/v1/users/{uid}/sessions/terminate-all", headers=h)).status_code == 403
    assert (await _get(db_session, Session, s.id)).status == "ACTIVE"
    assert (await client.get(f"/api/v1/users/{uid}/sessions")).status_code == 401


async def test_peer_operator_cannot_terminate_anothers_session(client, db_session, operator2_token, gateway):
    s = await _live(db_session, await _ssh_ready(db_session, with_ref=False))
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(operator2_token))
    assert r.status_code == 404
    assert (await _get(db_session, Session, s.id)).status == "ACTIVE"


# --- listing: ready grants are not sessions -------------------------------------------

async def test_user_view_separates_sessions_from_unused_grants(client, db_session, admin_token, gateway):
    in_use = await _ssh_ready(db_session, with_ref=False)
    unused = await _ssh_ready(db_session, with_ref=False)
    await _live(db_session, in_use, recording="RECORDING")
    r = await client.get(f"/api/v1/users/{in_use.user_id}/sessions", headers=auth_header(admin_token))
    body = r.json()
    assert r.status_code == 200 and body["session_limit"] == 2 and body["active_sessions"] == 1
    (sess,) = body["sessions"]
    assert sess["status"] == "ACTIVE" and sess["recording_status"] == "RECORDING" and sess["asset_name"] == "LINUX-DEV-01"
    assert [g["id"] for g in body["ready_grants"]] == [str(unused.jit_grant_id)]  # not the one in use
    assert "password" not in r.text and "hashed" not in r.text


# --- single termination -----------------------------------------------------------------

async def test_admin_terminate_closes_gateway_revokes_grant_and_audits(client, db_session, admin_token, gateway):
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req, recording="PENDING")
    gateway.held.add(s.id)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token),
                          json={"reason": "incident 42"})
    body = r.json()
    assert r.status_code == 200 and body["complete"] is True
    assert body["result"]["gateway"] == "closed" and body["result"]["grant_revoked"] is True
    assert gateway.closed == [s.id] and not gateway.held
    s = await _get(db_session, Session, s.id)
    assert s.status == "TERMINATED" and s.end_time is not None
    assert (await _get(db_session, JITGrant, req.jit_grant_id)).status == "REVOKED"
    (term,) = await _actions(db_session, "SESSION_TERMINATED")
    assert term.actor_username == "admin" and term.details["reason"] == "incident 42"
    assert term.details["gateway"] == "closed" and term.details["affected_user_id"] == str(req.user_id)
    assert len(await _actions(db_session, "JIT_REVOKED")) == 1


async def test_revoked_grant_can_never_launch_again(client, db_session, admin_token, operator_token, provider, gateway):
    req = await _ssh_ready(db_session)
    launched = (await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token),
                                  json=_launch_body(req))).json()
    r = await client.post(f"/api/v1/sessions/{launched['session_id']}/terminate", headers=auth_header(admin_token))
    assert r.status_code == 200
    again = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token),
                              json=_launch_body(req))
    assert again.status_code == 403  # NO_VALID_JIT_GRANT
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "NO_VALID_JIT_GRANT"


async def test_owner_ending_own_session_keeps_the_grant(client, db_session, operator_token, gateway):
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(operator_token))
    assert r.status_code == 200
    assert (await _get(db_session, Session, s.id)).status == "COMPLETED"
    assert (await _get(db_session, JITGrant, req.jit_grant_id)).status == "ACTIVE"


async def test_gateway_close_failure_is_reported_and_nothing_is_falsely_finalized(
    client, db_session, admin_token, gateway
):
    gateway.stuck = True
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req, recording="RECORDING")
    gateway.held.add(s.id)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))
    body = r.json()
    assert r.status_code == 207 and body["complete"] is False
    assert body["result"]["gateway"] == "failed" and body["result"]["errors"]
    assert (await _get(db_session, Session, s.id)).status == "TERMINATING"  # not TERMINATED
    rec = await _get(db_session, Recording, s.recording_id)
    assert rec.status == "RECORDING"  # not marked complete
    assert (await _get(db_session, JITGrant, req.jit_grant_id)).status == "ACTIVE"  # revoke only after teardown
    assert await _actions(db_session, "SESSION_TERMINATED") == []
    (failed,) = await _actions(db_session, "SESSION_TERMINATION_FAILED")
    assert failed.result == "FAILURE"
    # A retry once the gateway works completes the job.
    gateway.stuck = False
    again = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))
    assert again.status_code == 200 and again.json()["complete"] is True


@pytest.mark.parametrize("rec_status", ["PENDING", "RECORDING"])
async def test_recording_is_settled_by_what_exists_never_completed(client, db_session, admin_token, gateway, rec_status):
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req, recording=rec_status)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))
    assert r.json()["result"]["recording"] == "FAILED"
    rec = await _get(db_session, Recording, s.recording_id)
    assert rec.status == "FAILED" and rec.file_hash is None
    (row,) = await _actions(db_session, "RECORDING_FAILED")
    assert row.details["reason"] in ("RECORDING_NOT_STARTED", "RECORDING_NOT_FINALIZED")


async def test_a_recording_the_gateway_finalized_is_left_as_it_is(client, db_session, admin_token, gateway, monkeypatch):
    req = await _ssh_ready(db_session, with_ref=False)
    s = await _live(db_session, req, recording="RECORDING")
    gateway.held.add(s.id)
    original = gateway.get_live_connection
    finalized = []

    def release_and_finalize(sid):
        result = original(sid)
        if result is None and not finalized:
            finalized.append(True)  # the gateway finalizes its recording as the terminal closes
            import asyncio
            asyncio.get_event_loop().create_task(_finalize())
        return result

    async def _finalize():
        from app.database.session import async_session_factory
        async with async_session_factory() as db:
            rec = await db.get(Recording, s.recording_id)
            rec.status, rec.file_hash = "COMPLETED", "a" * 64
            await db.commit()
    gateway.get_live_connection = release_and_finalize
    monkeypatch.setattr(session_termination, "SETTLE_SECONDS", 2)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))
    assert r.json()["result"]["recording"] == "COMPLETED"
    assert await _actions(db_session, "RECORDING_FAILED") == []


async def test_terminating_a_finished_session_is_a_conflict(client, db_session, admin_token, gateway):
    s = await _live(db_session, await _ssh_ready(db_session, with_ref=False), status="COMPLETED")
    assert (await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))).status_code == 409


# --- terminate all ------------------------------------------------------------------------

async def test_terminate_all_ends_live_sessions_and_revokes_their_grants_only(client, db_session, admin_token, gateway):
    a = await _ssh_ready(db_session, with_ref=False)
    b = await _ssh_ready(db_session, with_ref=False)
    unused = await _ssh_ready(db_session, with_ref=False)
    done = await _ssh_ready(db_session, with_ref=False)
    sa, sb = await _live(db_session, a), await _live(db_session, b, status="STARTING")
    sd = await _live(db_session, done, status="COMPLETED")
    gateway.held.add(sa.id)
    r = await client.post(f"/api/v1/users/{a.user_id}/sessions/terminate-all", headers=auth_header(admin_token),
                          json={"reason": "offboarding"})
    body = r.json()
    assert r.status_code == 200 and body["complete"] and body["terminated"] == 2
    assert (await _get(db_session, Session, sa.id)).status == "TERMINATED"
    assert (await _get(db_session, Session, sb.id)).status == "TERMINATED"
    assert (await _get(db_session, Session, sd.id)).status == "COMPLETED"  # untouched
    assert (await _get(db_session, JITGrant, a.jit_grant_id)).status == "REVOKED"
    assert (await _get(db_session, JITGrant, b.jit_grant_id)).status == "REVOKED"
    assert (await _get(db_session, JITGrant, unused.jit_grant_id)).status == "ACTIVE"
    (summary,) = await _actions(db_session, "USER_SESSIONS_TERMINATED")
    assert summary.details["sessions"] == 2 and summary.actor_username == "admin" and summary.details["failed"] == []


async def test_terminate_all_reports_partial_failure(client, db_session, admin_token, gateway):
    a = await _ssh_ready(db_session, with_ref=False)
    b = await _ssh_ready(db_session, with_ref=False)
    sa, sb = await _live(db_session, a), await _live(db_session, b)
    gateway.held.update({sa.id, sb.id})
    gateway.never.add(sa.id)  # its connection never goes away
    r = await client.post(f"/api/v1/users/{a.user_id}/sessions/terminate-all", headers=auth_header(admin_token))
    body = r.json()
    assert r.status_code == 207 and body["complete"] is False and body["terminated"] == 1
    assert (await _get(db_session, Session, sa.id)).status == "TERMINATING"
    assert (await _get(db_session, Session, sb.id)).status == "TERMINATED"
    assert (await _get(db_session, JITGrant, a.jit_grant_id)).status == "ACTIVE"
    (summary,) = await _actions(db_session, "USER_SESSIONS_TERMINATED")
    assert summary.result == "FAILURE" and summary.details["failed"] == [sa.session_number]


async def test_terminate_all_unknown_user_is_404(client, admin_token, gateway):
    r = await client.post(f"/api/v1/users/{uuid.uuid4()}/sessions/terminate-all", headers=auth_header(admin_token))
    assert r.status_code == 404


# --- unused grant revocation ----------------------------------------------------------------

async def test_revoked_unused_grant_cannot_launch(client, db_session, admin_token, operator_token, provider):
    req = await _ssh_ready(db_session)
    r = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == "REVOKED" and r.json()["sessions_ended"] == 0
    launch = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token),
                               json=_launch_body(req))
    assert launch.status_code == 403
    assert (await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke",
                              headers=auth_header(operator_token))).status_code == 403


async def test_expired_grant_never_launches(client, db_session, operator_token, provider):
    req = await _ssh_ready(db_session)
    grant = await _get(db_session, JITGrant, req.jit_grant_id)
    grant.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    await db_session.commit()
    r = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
