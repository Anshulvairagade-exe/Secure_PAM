"""
Risk Centre: findings come only from persisted evidence, counts in the API equal the underlying rows,
rules are deterministic (thresholds, auto-resolve, reopen, dedupe), and access is role-checked.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.core.security import generate_event_id
from app.models.app_setting import AppSetting
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.risk_finding import RiskFinding
from app.services import risk_detector
from tests.conftest import auth_header

NOW = datetime.now(timezone.utc)


async def _event(db, action, *, minutes_ago=10, result="SUCCESS", target_type=None, target_id=None,
                 actor_username="system", actor_id=None, details=None, session_id=None):
    e = AuditLog(event_id=generate_event_id(), timestamp=NOW - timedelta(minutes=minutes_ago), action=action,
                 result=result, severity="INFO", actor_username=actor_username, actor_id=actor_id,
                 target_type=target_type, target_id=target_id, details=details or {}, session_id=session_id)
    db.add(e)
    await db.flush()
    return e


async def _asset(db):
    return (await db.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))).scalar_one()


async def test_empty_state_is_honest(client, db_session, admin_token):
    r = await client.get("/api/v1/risk/summary", headers=auth_header(admin_token))
    body = r.json()
    assert r.status_code == 200 and body["total_findings"] == 0
    assert all(v == 0 for v in body["open_by_severity"].values()) and body["last_evaluated_at"] is None


async def test_mfa_threshold_window_is_deterministic(db_session):
    for m in (5, 15, 25):  # three failures inside 60 minutes for user A
        await _event(db_session, "MFA_FAILURE", minutes_ago=m, result="FAILURE", target_type="user", target_id="kc-user-a")
    for m in (5, 200):     # two failures far apart for user B
        await _event(db_session, "MFA_FAILURE", minutes_ago=m, result="FAILURE", target_type="user", target_id="kc-user-b")
    await db_session.commit()
    stats = await risk_detector.evaluate(db_session)
    findings = {f.evidence["keycloak_user"]: f for f in (await db_session.execute(select(RiskFinding))).scalars()}
    assert findings["kc-user-a"].severity == "HIGH" and findings["kc-user-a"].occurrences == 3
    assert findings["kc-user-a"].evidence["max_in_60_min"] == 3
    assert findings["kc-user-b"].severity == "LOW"
    assert stats["created"] == 2
    again = await risk_detector.evaluate(db_session)  # dedupe: same evidence, no new rows
    assert again["created"] == 0 and again["updated"] == 2
    assert (await db_session.execute(select(func.count()).select_from(RiskFinding))).scalar_one() == 2


async def test_threshold_is_a_persisted_setting(db_session):
    for m in (5, 15):
        await _event(db_session, "MFA_FAILURE", minutes_ago=m, result="FAILURE", target_type="user", target_id="kc-x")
    db_session.add(AppSetting(key="risk.mfa_failure_threshold", value=2))
    await db_session.commit()
    await risk_detector.evaluate(db_session)
    assert (await db_session.execute(select(RiskFinding))).scalar_one().severity == "HIGH"


async def test_credential_finding_auto_resolves_and_reopens_on_new_evidence(db_session):
    asset = await _asset(db_session)
    await _event(db_session, "CREDENTIAL_RETRIEVAL_DENIED", minutes_ago=30, result="DENIED", target_type="asset",
                 target_id=str(asset.id))
    await db_session.commit()
    await risk_detector.evaluate(db_session)
    f = (await db_session.execute(select(RiskFinding))).scalar_one()
    assert f.status == "OPEN" and f.severity == "HIGH" and f.asset_id == asset.id

    await _event(db_session, "CREDENTIAL_RETRIEVED", minutes_ago=20, target_type="asset", target_id=str(asset.id))
    await db_session.commit()
    stats = await risk_detector.evaluate(db_session, now=NOW)
    await db_session.refresh(f)
    assert stats["auto_resolved"] == 1 and f.status == "RESOLVED" and f.status_note.startswith("auto:")

    f.status_changed_at = NOW - timedelta(minutes=15)
    await _event(db_session, "CREDENTIAL_RETRIEVAL_DENIED", minutes_ago=5, result="DENIED", target_type="asset",
                 target_id=str(asset.id))
    await db_session.commit()
    stats = await risk_detector.evaluate(db_session, now=NOW)
    await db_session.refresh(f)
    assert stats["reopened"] == 1 and f.status == "OPEN" and f.occurrences == 2


async def test_summary_and_list_counts_match_the_rows(client, db_session, admin_token):
    asset = await _asset(db_session)
    for m in (5, 6, 7):
        await _event(db_session, "MFA_FAILURE", minutes_ago=m, result="FAILURE", target_type="user", target_id="kc-1")
    await _event(db_session, "MFA_FAILURE", minutes_ago=5, result="FAILURE", target_type="user", target_id="kc-2")
    await _event(db_session, "CREDENTIAL_RETRIEVAL_FAILED", result="FAILURE", target_type="asset", target_id=str(asset.id))
    await db_session.commit()
    assert (await client.post("/api/v1/risk/evaluate", headers=auth_header(admin_token))).status_code == 200

    summary = (await client.get("/api/v1/risk/summary", headers=auth_header(admin_token))).json()
    rows = (await db_session.execute(select(RiskFinding))).scalars().all()
    for sev in risk_detector_severities():
        assert summary["open_by_severity"][sev] == sum(1 for r in rows if r.severity == sev and r.status != "RESOLVED")
    assert summary["total_findings"] == len(rows) == 3
    assert sum(sum(d["counts"].values()) for d in summary["new_findings_per_day"]) == len(rows)
    assert summary["last_evaluated_at"] is not None

    listing = (await client.get("/api/v1/risk/findings", headers=auth_header(admin_token))).json()
    assert listing["total"] == 3
    assert [i["severity"] for i in listing["items"]] == ["HIGH", "MEDIUM", "LOW"]  # prioritized
    high = (await client.get("/api/v1/risk/findings", params={"severity": "HIGH"}, headers=auth_header(admin_token))).json()
    assert high["total"] == 1
    by_asset = (await client.get("/api/v1/risk/findings", params={"asset_id": str(asset.id)},
                                 headers=auth_header(admin_token))).json()
    assert by_asset["total"] == 1 and by_asset["items"][0]["rule_code"] == "CREDENTIAL_FAILED"

    detail = (await client.get(f"/api/v1/risk/findings/{by_asset['items'][0]['id']}", headers=auth_header(admin_token))).json()
    assert detail["asset_name"] == "LINUX-DEV-01" and detail["evidence_events"][0]["found"] is True
    assert detail["evidence_events"][0]["action"] == "CREDENTIAL_RETRIEVAL_FAILED"


def risk_detector_severities():
    return ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


async def test_roles_read_vs_manage(client, db_session, admin_token, auditor_token, operator_token):
    await _event(db_session, "MFA_FAILURE", result="FAILURE", target_type="user", target_id="kc-9")
    await db_session.commit()
    await client.post("/api/v1/risk/evaluate", headers=auth_header(admin_token))
    fid = (await client.get("/api/v1/risk/findings", headers=auth_header(admin_token))).json()["items"][0]["id"]
    assert (await client.get("/api/v1/risk/summary", headers=auth_header(auditor_token))).status_code == 200
    assert (await client.get("/api/v1/risk/summary", headers=auth_header(operator_token))).status_code == 403
    assert (await client.patch(f"/api/v1/risk/findings/{fid}", json={"status": "ACKNOWLEDGED"},
                               headers=auth_header(auditor_token))).status_code == 403
    assert (await client.post("/api/v1/risk/evaluate", headers=auth_header(auditor_token))).status_code == 403
    r = await client.patch(f"/api/v1/risk/findings/{fid}", json={"status": "ACKNOWLEDGED", "note": "known"},
                           headers=auth_header(admin_token))
    assert r.status_code == 200 and r.json()["status"] == "ACKNOWLEDGED"
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "RISK_FINDING_UPDATED"))).scalar_one()
    assert audit.details["before"] == "OPEN" and audit.details["after"] == "ACKNOWLEDGED"


async def test_external_ingest_contract_upserts(client, db_session, admin_token):
    asset = await _asset(db_session)
    body = {"source": "wazuh", "external_id": "rule-5710:host-1", "title": "SSH brute force", "description": "d",
            "severity": "HIGH", "remediation": "Block the source", "observed_at": NOW.isoformat(),
            "asset_id": str(asset.id), "evidence": {"alerts": 12}}
    first = await client.post("/api/v1/risk/findings/ingest", json=body, headers=auth_header(admin_token))
    second = await client.post("/api/v1/risk/findings/ingest", json=body, headers=auth_header(admin_token))
    assert first.status_code == second.status_code == 201 and first.json()["id"] == second.json()["id"]
    assert second.json()["occurrences"] == 2 and second.json()["subject"] == "LINUX-DEV-01"
    reserved = await client.post("/api/v1/risk/findings/ingest", json={**body, "source": "securepam-detector"},
                                 headers=auth_header(admin_token))
    assert reserved.status_code == 422
