"""Concurrent session limit: counting, atomicity, admin policy API."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.recording import Recording
from app.models.session import Session
from app.services.session_policy import STARTING_GRACE
from tests.conftest import auth_header
from tests.test_ssh_session_endpoints import (  # noqa: F401  (fixtures)
    _actions, _launch_body, _recording_storage, _ssh_ready, provider,
)


async def _launch(client, token, req):
    return await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(token), json=_launch_body(req))


async def _ready_requests(db, n, username="operator"):
    """n independent approved requests, each with its own live grant (one credential reference)."""
    out = [await _ssh_ready(db, username=username, with_ref=True)]
    for _ in range(n - 1):
        out.append(await _ssh_ready(db, username=username, with_ref=False))
    return out


async def test_third_concurrent_launch_is_rejected_with_the_limit(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 3)
    assert (await _launch(client, operator_token, reqs[0])).status_code == 201
    assert (await _launch(client, operator_token, reqs[1])).status_code == 201
    r = await _launch(client, operator_token, reqs[2])
    assert r.status_code == 409
    assert "limit reached" in r.json()["detail"] and "2 of 2" in r.json()["detail"]
    assert len((await db_session.execute(select(Session))).scalars().all()) == 2
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "SESSION_LIMIT_REACHED" and denied.details["limit"] == 2


async def test_approved_requests_and_unused_grants_do_not_count(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 5)  # five live grants, nothing launched
    assert (await _launch(client, operator_token, reqs[0])).status_code == 201
    assert (await _launch(client, operator_token, reqs[1])).status_code == 201  # 2 live of 5 grants


async def test_ending_a_session_frees_a_slot(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 3)
    first = (await _launch(client, operator_token, reqs[0])).json()
    await _launch(client, operator_token, reqs[1])
    assert (await _launch(client, operator_token, reqs[2])).status_code == 409
    done = await client.post(f"/api/v1/sessions/{first['session_id']}/terminate", headers=auth_header(operator_token))
    assert done.status_code == 200
    assert (await _launch(client, operator_token, reqs[2])).status_code == 201


async def test_simultaneous_launches_cannot_exceed_the_limit(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 5)
    results = await asyncio.gather(*[_launch(client, operator_token, r) for r in reqs])
    codes = sorted(r.status_code for r in results)
    assert codes == [201, 201, 409, 409, 409], codes
    live = (await db_session.execute(select(Session).where(Session.status == "STARTING"))).scalars().all()
    assert len(live) == 2


async def test_limit_is_per_user(client, db_session, operator_token, operator2_token, provider):
    mine = await _ready_requests(db_session, 3)
    for r in mine[:2]:
        await _launch(client, operator_token, r)
    assert (await _launch(client, operator_token, mine[2])).status_code == 409
    theirs = await _ssh_ready(db_session, username="operator2", with_ref=False)
    assert (await _launch(client, operator2_token, theirs)).status_code == 201


async def test_abandoned_starting_sessions_do_not_hold_a_slot(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 3)
    ids = [(await _launch(client, operator_token, r)).json()["session_id"] for r in reqs[:2]]
    old = datetime.now(timezone.utc) - STARTING_GRACE - timedelta(seconds=30)
    for sid in ids:
        row = await db_session.get(Session, sid)
        row.created_at = old
    await db_session.commit()
    assert (await _launch(client, operator_token, reqs[2])).status_code == 201
    db_session.expire_all()
    stale = await db_session.get(Session, ids[0])
    assert stale.status == "FAILED"  # closed out as never connected, not left dangling


async def test_client_supplied_identity_cannot_dodge_the_limit(client, db_session, operator_token, provider):
    reqs = await _ready_requests(db_session, 3)
    for r in reqs[:2]:
        await _launch(client, operator_token, r)
    r = await client.post("/api/v1/sessions/ssh/launch", headers=auth_header(operator_token),
                          json={**_launch_body(reqs[2]), "user_id": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 422


# --- admin policy API ---------------------------------------------------------------

async def test_policy_default_and_visibility(client, operator_token):
    r = await client.get("/api/v1/settings/session-policy", headers=auth_header(operator_token))
    assert r.status_code == 200 and r.json()["max_concurrent_sessions"] == 2 and r.json()["max_allowed"] == 20


async def test_only_admin_can_change_policy(client, db_session, operator_token, approver_token, auditor_token):
    for token in (operator_token, approver_token, auditor_token):
        r = await client.put("/api/v1/settings/session-policy", headers=auth_header(token),
                             json={"max_concurrent_sessions": 9})
        assert r.status_code == 403
    assert (await client.put("/api/v1/settings/session-policy", json={"max_concurrent_sessions": 9})).status_code == 401
    assert (await client.get("/api/v1/settings/session-policy", headers=auth_header(operator_token))
            ).json()["max_concurrent_sessions"] == 2


@pytest.mark.parametrize("value", [0, -1, 21, "many", None, 1.5])
async def test_policy_validation(client, admin_token, value):
    r = await client.put("/api/v1/settings/session-policy", headers=auth_header(admin_token),
                         json={"max_concurrent_sessions": value})
    assert r.status_code == 422


async def test_policy_rejects_extra_fields(client, admin_token):
    r = await client.put("/api/v1/settings/session-policy", headers=auth_header(admin_token),
                         json={"max_concurrent_sessions": 3, "updated_by": "x"})
    assert r.status_code == 422


async def test_changing_the_limit_is_audited_and_enforced(client, db_session, admin_token, operator_token, provider):
    r = await client.put("/api/v1/settings/session-policy", headers=auth_header(admin_token),
                         json={"max_concurrent_sessions": 1})
    assert r.status_code == 200 and r.json()["max_concurrent_sessions"] == 1
    (row,) = await _actions(db_session, "SESSION_POLICY_CHANGED")
    assert row.actor_username == "admin" and row.details == {"before": 2, "after": 1}
    reqs = await _ready_requests(db_session, 2)
    assert (await _launch(client, operator_token, reqs[0])).status_code == 201
    blocked = await _launch(client, operator_token, reqs[1])
    assert blocked.status_code == 409 and "1 of 1" in blocked.json()["detail"]

    raised = await client.put("/api/v1/settings/session-policy", headers=auth_header(admin_token),
                              json={"max_concurrent_sessions": 3})
    assert raised.status_code == 200
    assert (await _launch(client, operator_token, reqs[1])).status_code == 201
