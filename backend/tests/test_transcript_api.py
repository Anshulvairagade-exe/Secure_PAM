"""Transcript endpoints: access control, integrity, audit, honest absence."""

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.recording import Recording
from app.services.command_transcript import TranscriptTracker, transcript_path, write_transcript
from tests.conftest import auth_header
from tests.test_session_endpoints import _make_session, storage  # noqa: F401  (fixture)


async def _actions(db, action):
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


async def _terminal_recording(db, storage, with_transcript=True, rtype="TERMINAL"):
    s = await _make_session(db)
    path = str(storage / f"session_{s.id}")
    meta = None
    if with_transcript:
        t = TranscriptTracker(lambda: 1.0)
        t.input("whoami\r")
        t.output("whoami\r\nkali\r\n")
        meta = write_transcript(path, session_number=s.session_number, events=t.events())
    rec = Recording(session_id=s.id, recording_type=rtype, status="COMPLETED", file_path=path,
                    metadata_={"transcript": meta} if meta else None)
    db.add(rec)
    await db.commit()
    return rec, path


async def test_auditor_reads_transcript_and_view_is_audited(client, db_session, storage, auditor_token):
    rec, _ = await _terminal_recording(db_session, storage)
    r = await client.get(f"/api/v1/recordings/{rec.id}/transcript", headers=auth_header(auditor_token))
    body = r.json()
    assert r.status_code == 200 and body["available"] is True
    (event,) = body["transcript"]["events"]
    assert event["input"] == "whoami" and event["output"] == "kali" and event["execution_verified"] is False
    assert "storage" not in r.text and str(storage) not in r.text
    (viewed,) = await _actions(db_session, "TRANSCRIPT_VIEWED")
    assert viewed.actor_username == "auditor" and viewed.target_id == str(rec.id)


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token"])
async def test_transcript_requires_recordings_read(client, db_session, storage, request, token_fixture):
    rec, _ = await _terminal_recording(db_session, storage)
    r = await client.get(f"/api/v1/recordings/{rec.id}/transcript",
                         headers=auth_header(request.getfixturevalue(token_fixture)))
    assert r.status_code == 403
    assert (await client.get(f"/api/v1/recordings/{rec.id}/transcript")).status_code == 401


async def test_tampered_transcript_is_refused_and_audited(client, db_session, storage, auditor_token):
    rec, path = await _terminal_recording(db_session, storage)
    with open(transcript_path(path), "a") as handle:
        handle.write(" ")
    r = await client.get(f"/api/v1/recordings/{rec.id}/transcript", headers=auth_header(auditor_token))
    assert r.status_code == 409
    assert len(await _actions(db_session, "TRANSCRIPT_INTEGRITY_FAILED")) == 1
    assert await _actions(db_session, "TRANSCRIPT_VIEWED") == []


async def test_missing_transcript_is_reported_not_invented(client, db_session, storage, auditor_token):
    rec, _ = await _terminal_recording(db_session, storage, with_transcript=False)
    body = (await client.get(f"/api/v1/recordings/{rec.id}/transcript", headers=auth_header(auditor_token))).json()
    assert body["available"] is False and "No transcript was captured" in body["reason"] and body["transcript"] is None


async def test_rdp_video_has_no_command_transcript_without_telemetry(client, db_session, storage, auditor_token):
    rec, _ = await _terminal_recording(db_session, storage, with_transcript=False, rtype="VIDEO")
    body = (await client.get(f"/api/v1/recordings/{rec.id}/transcript", headers=auth_header(auditor_token))).json()
    assert body["available"] is False and "4688" in body["reason"]


async def test_export_needs_download_permission_and_is_audited(client, db_session, storage, auditor_token, admin_token):
    rec, _ = await _terminal_recording(db_session, storage)
    url = f"/api/v1/recordings/{rec.id}/transcript/export"
    assert (await client.get(url, headers=auth_header(auditor_token))).status_code == 403
    r = await client.get(url, headers=auth_header(admin_token))
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert len(await _actions(db_session, "TRANSCRIPT_EXPORTED")) == 1


async def test_list_flags_transcript_availability(client, db_session, storage, auditor_token):
    await _terminal_recording(db_session, storage)
    items = (await client.get("/api/v1/recordings/", headers=auth_header(auditor_token))).json()["items"]
    assert items[0]["transcript_available"] is True and "transcript" not in str(items[0]).replace("transcript_available", "")
