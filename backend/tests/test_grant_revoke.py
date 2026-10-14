"""
POST /jit-grants/{id}/revoke — an administrator can kill JIT access early.

Revoking ends every live session the grant authorized (fail closed) and is
audited as JIT_REVOKED. Idempotent: revoking a dead grant reports its
state. No response carries a credential or token.
"""

import uuid

from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session, SessionEvent
from tests.conftest import auth_header
from tests.test_credential_service import _scenario

NIL = "00000000-0000-0000-0000-000000000000"


async def _live_session(db, req, status="ACTIVE") -> Session:
    s = Session(
        session_number=f"SES-{uuid.uuid4().hex[:6].upper()}",
        user_id=req.user_id, asset_id=req.asset_id, request_id=req.access_request_id,
        jit_grant_id=req.jit_grant_id, protocol="SSH", status=status,
    )
    db.add(s)
    await db.commit()
    return s


async def _actions(db, action) -> list[AuditLog]:
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


async def test_admin_revokes_active_grant_and_live_session_expires(client, db_session, admin_token):
    req = await _scenario(db_session)
    s = await _live_session(db_session, req)

    r = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "REVOKED" and body["sessions_ended"] == 1 and body["revoked_at"]

    grant = await db_session.get(JITGrant, req.jit_grant_id)
    assert grant.status == "REVOKED" and grant.revoked_at is not None
    await db_session.refresh(s)
    assert s.status == "EXPIRED" and s.end_time is not None

    events = (await db_session.execute(
        select(SessionEvent).where(SessionEvent.session_id == s.id))).scalars().all()
    assert [e.event_type for e in events] == ["SESSION_ENDED_BY_GRANT"]

    (revoked,) = await _actions(db_session, "JIT_REVOKED")
    assert revoked.result == "SUCCESS" and revoked.target_id == str(req.jit_grant_id)
    assert revoked.details["sessions_ended"] == 1


async def test_revoke_is_idempotent(client, db_session, admin_token):
    req = await _scenario(db_session)
    first = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
    second = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
    assert first.status_code == 200 and second.status_code == 200
    assert second.json() == {**first.json(), "sessions_ended": 0}


async def test_revoke_expired_grant_is_a_noop(client, db_session, admin_token):
    req = await _scenario(db_session, grant_status="EXPIRED")
    r = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == "EXPIRED"


async def test_operator_cannot_revoke(client, db_session, operator_token):
    req = await _scenario(db_session)
    r = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(operator_token))
    assert r.status_code == 403
    assert (await db_session.get(JITGrant, req.jit_grant_id)).status == "ACTIVE"
    assert await _actions(db_session, "JIT_REVOKED") == []


async def test_revoke_unknown_grant_404(client, db_session, admin_token):
    r = await client.post(f"/api/v1/jit-grants/{NIL}/revoke", headers=auth_header(admin_token))
    assert r.status_code == 404


async def test_revoke_requires_auth(client, db_session):
    req = await _scenario(db_session)
    r = await client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke")
    assert r.status_code == 401
