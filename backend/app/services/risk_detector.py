"""
Deterministic, evidence-backed Risk Centre detector.

Reads only SecurePAM's own persisted records (audit_logs, risk_events/access_requests, sessions) and
turns them into findings with fixed, documented rules. No randomness, no ML, no synthetic data: the
same records always produce the same findings. Every finding carries its evidence (audit event ids,
request numbers, counts) so a reviewer can verify it.

Rules (RULES below is the single source of truth, also served to the UI):
  MFA_FAILURES          MFA_FAILURE per identity. >= threshold within 60 min -> HIGH, otherwise LOW.
  LAUNCH_DENIALS        SESSION_LAUNCH_DENIED per user, >= threshold within 60 min -> MEDIUM.
  CREDENTIAL_DENIED     CREDENTIAL_RETRIEVAL_DENIED per asset -> HIGH (auto-resolves after a later CREDENTIAL_RETRIEVED).
  CREDENTIAL_FAILED     CREDENTIAL_RETRIEVAL_FAILED per asset -> MEDIUM (auto-resolves likewise).
  CREDENTIAL_REF_BROKEN CREDENTIAL_REF_CHECKED FAILURE per asset -> MEDIUM (auto-resolves when the latest check passes).
  RECORDING_FAILED      RECORDING_FAILED per recording -> HIGH (a session ran without a complete recording).
  TLS_VALIDATION        TLS_VALIDATION_FAILED per application -> MEDIUM (auto-resolves after a later SESSION_PREPARED).
  EGRESS_BLOCKED        DESTINATION_DENIED per application -> LOW (the isolated browser tried unregistered hosts).
  HIGH_RISK_ACCESS      risk engine CRITICAL -> MEDIUM, HIGH -> LOW, per (user, target): review approvals.

Lifecycle: OPEN -> ACKNOWLEDGED / RESOLVED by an administrator, or RESOLVED automatically by the
auto-resolve condition. New evidence after a resolution reopens the finding. Thresholds are persisted
application settings (risk.mfa_failure_threshold, risk.launch_denial_threshold).
"""

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.access_request import AccessRequest
from app.models.app_setting import AppSetting
from app.models.application import Application
from app.models.asset import Asset
from app.models.audit import AuditLog, RiskEvent
from app.models.risk_finding import RiskFinding
from app.models.session import Session
from app.models.user import User

SOURCE = "securepam-detector"
LOOKBACK_DAYS = 30
WINDOW = timedelta(minutes=60)
MAX_EVIDENCE = 25
DEFAULT_THRESHOLDS = {"risk.mfa_failure_threshold": 3, "risk.launch_denial_threshold": 5}

RULES = {
    "MFA_FAILURES": ("MFA_FAILURE events per identity; HIGH when >= threshold within 60 minutes, otherwise LOW.",
                     "Confirm with the user; if unexpected, reset their authenticator and review the source IPs."),
    "LAUNCH_DENIALS": ("Repeated SESSION_LAUNCH_DENIED for one user (>= threshold within 60 minutes): MEDIUM.",
                       "Check whether the user lacks a valid request/grant or is probing targets; review the denial reasons."),
    "CREDENTIAL_DENIED": ("CREDENTIAL_RETRIEVAL_DENIED for an asset: HIGH. Auto-resolves after a later successful retrieval.",
                          "OpenBao refused the backend's reader token: rotate it and check securepam-app.hcl covers the path."),
    "CREDENTIAL_FAILED": ("CREDENTIAL_RETRIEVAL_FAILED for an asset: MEDIUM. Auto-resolves after a later successful retrieval.",
                          "Check the secret exists at the referenced path with the expected fields, and OpenBao health."),
    "CREDENTIAL_REF_BROKEN": ("Latest credential-reference check for an asset failed: MEDIUM. Auto-resolves when it passes.",
                              "Run the reference check from Vault references and fix the secret or the binding."),
    "RECORDING_FAILED": ("RECORDING_FAILED: a session has no complete recording. HIGH.",
                         "Check recording storage and the gateway; review the session's command transcript/events instead."),
    "TLS_VALIDATION": ("TLS_VALIDATION_FAILED for an application: MEDIUM. Auto-resolves after a later successful launch.",
                       "Fix the application's certificate (issuer, SAN) or the isolated browser's trust policy. Never bypass."),
    "EGRESS_BLOCKED": ("DESTINATION_DENIED from the isolated browser for an application: LOW.",
                       "Review the denied hosts. Browser background traffic is expected; anything else may indicate misuse."),
    "HIGH_RISK_ACCESS": ("Risk engine scored requests CRITICAL (finding MEDIUM) or HIGH (finding LOW) for a user/target.",
                         "Review the approvals and factors; tighten policy or business-hours rules if this is unexpected."),
}


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def _max_in_window(times: list[datetime]) -> int:
    times = sorted(times)
    best, start = 0, 0
    for end in range(len(times)):
        while times[end] - times[start] > WINDOW:
            start += 1
        best = max(best, end - start + 1)
    return best


async def thresholds(db: AsyncSession) -> dict:
    out = dict(DEFAULT_THRESHOLDS)
    for row in (await db.execute(select(AppSetting).where(AppSetting.key.in_(list(DEFAULT_THRESHOLDS))))).scalars():
        if isinstance(row.value, int) and row.value >= 1:
            out[row.key] = row.value
    return out


class _Candidate:
    def __init__(self, rule, fingerprint, *, severity, title, subject, events: list, evidence_extra=None,
                 asset_id=None, application_id=None, user_id=None, session_id=None, resolved=False, resolve_note=""):
        self.rule, self.fingerprint, self.severity, self.title, self.subject = rule, fingerprint, severity, title, subject
        self.events = events  # list of (timestamp, reference)
        self.evidence_extra = evidence_extra or {}
        self.asset_id, self.application_id, self.user_id, self.session_id = asset_id, application_id, user_id, session_id
        self.resolved, self.resolve_note = resolved, resolve_note


async def _audit(db, actions: Iterable[str], since: datetime, result: Optional[str] = None):
    q = select(AuditLog).where(AuditLog.action.in_(list(actions)), AuditLog.timestamp >= since)
    if result:
        q = q.where(AuditLog.result == result)
    return (await db.execute(q.order_by(AuditLog.timestamp))).scalars().all()


def _uuid(value):
    import uuid
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


async def collect(db: AsyncSession, now: Optional[datetime] = None) -> list[_Candidate]:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=LOOKBACK_DAYS)
    th = await thresholds(db)
    out: list[_Candidate] = []
    assets = {a.id: a.name for a in (await db.execute(select(Asset))).scalars()}
    apps = {a.id: a.name for a in (await db.execute(select(Application))).scalars()}
    users_by_ext = {u.external_id: u for u in (await db.execute(select(User))).scalars() if u.external_id}

    # MFA failures per identity (Keycloak subject in target_id)
    by_user = defaultdict(list)
    for e in await _audit(db, ["MFA_FAILURE"], since):
        by_user[e.target_id or e.actor_username].append(e)
    for key, evs in by_user.items():
        peak = _max_in_window([e.timestamp for e in evs])
        sev = "HIGH" if peak >= th["risk.mfa_failure_threshold"] else "LOW"
        local = users_by_ext.get(key)
        out.append(_Candidate("MFA_FAILURES", _fp("MFA_FAILURES", key), severity=sev,
                              title="Repeated MFA failures" if sev == "HIGH" else "MFA failure observed",
                              subject=local.username if local else (evs[-1].actor_username or str(key)),
                              events=[(e.timestamp, e.event_id) for e in evs],
                              evidence_extra={"max_in_60_min": peak, "threshold": th["risk.mfa_failure_threshold"],
                                              "keycloak_user": key, "source_ips": sorted({e.source_ip for e in evs if e.source_ip})},
                              user_id=local.id if local else None))

    # Launch denials per user
    by_actor = defaultdict(list)
    for e in await _audit(db, ["SESSION_LAUNCH_DENIED"], since):
        if e.actor_id:
            by_actor[e.actor_id].append(e)
    for actor_id, evs in by_actor.items():
        peak = _max_in_window([e.timestamp for e in evs])
        if peak >= th["risk.launch_denial_threshold"]:
            reasons = defaultdict(int)
            for e in evs:
                reasons[(e.details or {}).get("reason", "unknown")] += 1
            out.append(_Candidate("LAUNCH_DENIALS", _fp("LAUNCH_DENIALS", actor_id), severity="MEDIUM",
                                  title="Repeated session launch denials", subject=evs[-1].actor_username,
                                  events=[(e.timestamp, e.event_id) for e in evs],
                                  evidence_extra={"max_in_60_min": peak, "threshold": th["risk.launch_denial_threshold"],
                                                  "reasons": dict(sorted(reasons.items()))},
                                  user_id=actor_id))

    # Credential retrieval problems per asset, auto-resolved by a later success
    successes = defaultdict(list)
    for e in await _audit(db, ["CREDENTIAL_RETRIEVED"], since):
        successes[e.target_id].append(e.timestamp)
    for rule, action, sev, title in (("CREDENTIAL_DENIED", "CREDENTIAL_RETRIEVAL_DENIED", "HIGH", "Credential retrieval denied by OpenBao"),
                                     ("CREDENTIAL_FAILED", "CREDENTIAL_RETRIEVAL_FAILED", "MEDIUM", "Credential retrieval failed")):
        grouped = defaultdict(list)
        for e in await _audit(db, [action], since):
            grouped[e.target_id].append(e)
        for target, evs in grouped.items():
            last_bad = evs[-1].timestamp
            fixed = any(t > last_bad for t in successes.get(target, []))
            aid = _uuid(target)
            out.append(_Candidate(rule, _fp(rule, target), severity=sev, title=title,
                                  subject=assets.get(aid, str(target)), events=[(e.timestamp, e.event_id) for e in evs],
                                  asset_id=aid if aid in assets else None, resolved=fixed,
                                  resolve_note="auto: a later credential retrieval succeeded"))

    # Credential reference checks: latest result per asset decides
    checks = defaultdict(list)
    for e in await _audit(db, ["CREDENTIAL_REF_CHECKED"], since):
        if e.target_type == "asset":
            checks[e.target_id].append(e)
    for target, evs in checks.items():
        failures = [e for e in evs if e.result != "SUCCESS"]
        if not failures:
            continue
        aid = _uuid(target)
        out.append(_Candidate("CREDENTIAL_REF_BROKEN", _fp("CREDENTIAL_REF_BROKEN", target), severity="MEDIUM",
                              title="Credential reference check failing", subject=assets.get(aid, str(target)),
                              events=[(e.timestamp, e.event_id) for e in failures],
                              evidence_extra={"last_results": [(e.details or {}).get("result") for e in failures[-5:]]},
                              asset_id=aid if aid in assets else None, resolved=evs[-1].result == "SUCCESS",
                              resolve_note="auto: the latest reference check passed"))

    # Recording failures, one finding per recording
    for e in await _audit(db, ["RECORDING_FAILED"], since):
        session = await db.get(Session, e.session_id) if e.session_id else None
        subject = session.session_number if session else str(e.target_id)
        out.append(_Candidate("RECORDING_FAILED", _fp("RECORDING_FAILED", e.target_id), severity="HIGH",
                              title="Session recording failed", subject=subject, events=[(e.timestamp, e.event_id)],
                              evidence_extra={"reason": (e.details or {}).get("reason")},
                              session_id=e.session_id, asset_id=session.asset_id if session else None,
                              application_id=session.application_id if session else None,
                              user_id=session.user_id if session else None))

    # TLS validation failures per application, auto-resolved by a later successful launch
    prepared = defaultdict(list)
    for e in await _audit(db, ["SESSION_PREPARED"], since):
        prepared[e.target_id].append(e.timestamp)
    tls = defaultdict(list)
    for e in await _audit(db, ["TLS_VALIDATION_FAILED"], since):
        tls[e.target_id].append(e)
    for target, evs in tls.items():
        appid = _uuid(target)
        out.append(_Candidate("TLS_VALIDATION", _fp("TLS_VALIDATION", target), severity="MEDIUM",
                              title="Application certificate failed validation", subject=apps.get(appid, str(target)),
                              events=[(e.timestamp, e.event_id) for e in evs], application_id=appid if appid in apps else None,
                              resolved=any(t > evs[-1].timestamp for t in prepared.get(target, [])),
                              resolve_note="auto: a later isolated-browser launch passed TLS validation"))

    # Isolated-browser egress denials per application (via the session)
    sessions_app = {}
    by_app = defaultdict(list)
    for e in await _audit(db, ["DESTINATION_DENIED"], since):
        if e.session_id not in sessions_app:
            s = await db.get(Session, e.session_id) if e.session_id else None
            sessions_app[e.session_id] = s.application_id if s else None
        by_app[sessions_app[e.session_id]].append(e)
    for appid, evs in by_app.items():
        hosts = defaultdict(int)
        for e in evs:
            hosts[f"{(e.details or {}).get('host')}:{(e.details or {}).get('port')}"] += 1
        out.append(_Candidate("EGRESS_BLOCKED", _fp("EGRESS_BLOCKED", appid), severity="LOW",
                              title="Isolated browser blocked unregistered destinations",
                              subject=apps.get(appid, "unknown application"), events=[(e.timestamp, e.event_id) for e in evs],
                              evidence_extra={"denied_hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:10])},
                              application_id=appid if appid in apps else None))

    # High-risk access evaluations (risk engine), per user + target
    rows = (await db.execute(
        select(RiskEvent, AccessRequest).join(AccessRequest, AccessRequest.id == RiskEvent.request_id)
        .where(RiskEvent.evaluated_at >= since, RiskEvent.risk_level.in_(("HIGH", "CRITICAL")))
        .order_by(RiskEvent.evaluated_at)
    )).all()
    grouped = defaultdict(list)
    for ev, req in rows:
        grouped[(ev.user_id, req.asset_id or req.application_id)].append((ev, req))
    for (user_id, target), items in grouped.items():
        critical = any(ev.risk_level == "CRITICAL" for ev, _ in items)
        factors = defaultdict(int)
        for ev, _ in items:
            for f in ev.risk_factors or []:
                factors[f.get("code", "?")] += 1
        first_req = items[0][1]
        name = assets.get(first_req.asset_id) or apps.get(first_req.application_id) or "target"
        user = await db.get(User, user_id)
        out.append(_Candidate("HIGH_RISK_ACCESS", _fp("HIGH_RISK_ACCESS", user_id, target),
                              severity="MEDIUM" if critical else "LOW", title="High-risk access requests",
                              subject=f"{user.username if user else user_id} → {name}",
                              events=[(ev.evaluated_at, req.request_number) for ev, req in items],
                              evidence_extra={"max_score": max(ev.risk_score for ev, _ in items),
                                              "levels": sorted({ev.risk_level for ev, _ in items}),
                                              "factor_counts": dict(sorted(factors.items()))},
                              user_id=user_id, asset_id=first_req.asset_id, application_id=first_req.application_id))
    return out


async def evaluate(db: AsyncSession, now: Optional[datetime] = None) -> dict:
    """Upsert findings from the current records. Returns counts. Commits."""
    now = now or datetime.now(timezone.utc)
    stats = {"evaluated": 0, "created": 0, "updated": 0, "reopened": 0, "auto_resolved": 0}
    existing = {f.fingerprint: f for f in (await db.execute(
        select(RiskFinding).where(RiskFinding.source == SOURCE))).scalars()}
    for c in await collect(db, now):
        stats["evaluated"] += 1
        times = [t for t, _ in c.events]
        evidence = {"rule": c.rule, "count": len(c.events), "references": [r for _, r in c.events[-MAX_EVIDENCE:]],
                    **c.evidence_extra}
        f = existing.get(c.fingerprint)
        if f is None:
            f = RiskFinding(fingerprint=c.fingerprint, rule_code=c.rule, source=SOURCE, status="OPEN",
                            remediation=RULES[c.rule][1], description=RULES[c.rule][0])
            db.add(f)
            stats["created"] += 1
        else:
            stats["updated"] += 1
            if f.status == "RESOLVED" and f.status_changed_at and max(times) > f.status_changed_at and not c.resolved:
                f.status, f.status_changed_at, f.status_changed_by = "OPEN", now, None
                f.status_note = "reopened: new evidence after resolution"
                stats["reopened"] += 1
        f.title, f.severity, f.subject = c.title, c.severity, c.subject[:255]
        f.asset_id, f.application_id, f.user_id, f.session_id = c.asset_id, c.application_id, c.user_id, c.session_id
        f.first_seen, f.last_seen, f.occurrences, f.evidence = min(times), max(times), len(times), evidence
        if c.resolved and f.status != "RESOLVED":
            f.status, f.status_changed_at, f.status_changed_by, f.status_note = "RESOLVED", now, None, c.resolve_note
            stats["auto_resolved"] += 1
    setting = await db.get(AppSetting, "risk.last_evaluated_at")
    if setting is None:
        db.add(AppSetting(key="risk.last_evaluated_at", value=now.isoformat()))
    else:
        setting.value = now.isoformat()
    await db.commit()
    return stats
