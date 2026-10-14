"""
Risk Centre API. Reads need risk:read (ADMIN, APPROVER, AUDITOR); changes need risk:manage (ADMIN).

Every number returned is computed from persisted rows (risk_findings, risk_events, audit_logs) at
request time; nothing is estimated or synthesized. See app.services.risk_detector for the rules.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.models.app_setting import AppSetting
from app.models.application import Application
from app.models.asset import Asset
from app.models.audit import AuditLog, RiskEvent
from app.models.risk_finding import RiskFinding
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.services import risk_detector

router = APIRouter(prefix="/risk", tags=["Risk Centre"])

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
_SEV_RANK = case({s: i for i, s in enumerate(SEVERITIES)}, value=RiskFinding.severity, else_=len(SEVERITIES))


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    rule_code: str
    source: str
    title: str
    description: str
    severity: str
    status: str
    subject: str
    asset_id: Optional[uuid.UUID]
    application_id: Optional[uuid.UUID]
    user_id: Optional[uuid.UUID]
    session_id: Optional[uuid.UUID]
    evidence: Dict[str, Any]
    remediation: str
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    status_changed_at: Optional[datetime]
    status_note: Optional[str]


class EvidenceEvent(BaseModel):
    reference: str
    found: bool
    timestamp: Optional[datetime] = None
    action: Optional[str] = None
    actor: Optional[str] = None
    result: Optional[str] = None
    session_id: Optional[uuid.UUID] = None


class FindingDetail(FindingOut):
    asset_name: Optional[str]
    application_name: Optional[str]
    username: Optional[str]
    evidence_events: List[EvidenceEvent]


class DayPoint(BaseModel):
    day: str
    counts: Dict[str, int]


class RiskSummary(BaseModel):
    window_days: int
    open_by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_rule: Dict[str, int]
    by_source: Dict[str, int]
    new_findings_per_day: List[DayPoint]
    access_risk_by_level: Dict[str, int]
    access_risk_per_day: List[DayPoint]
    total_findings: int
    last_evaluated_at: Optional[str]
    rules: Dict[str, str]
    thresholds: Dict[str, int]


def _days(window: int, now: datetime) -> list[str]:
    return [(now - timedelta(days=i)).date().isoformat() for i in range(window - 1, -1, -1)]


@router.get("/summary", response_model=RiskSummary)
async def risk_summary(days: int = Query(30, ge=1, le=90), db: AsyncSession = Depends(get_db),
                       _: User = Depends(PermissionChecker("risk", "read"))):
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    open_q = select(RiskFinding.severity, func.count()).where(RiskFinding.status != "RESOLVED").group_by(RiskFinding.severity)
    open_by = {s: 0 for s in SEVERITIES} | dict((await db.execute(open_q)).all())
    by_status = {s: 0 for s in STATUSES} | dict((await db.execute(
        select(RiskFinding.status, func.count()).group_by(RiskFinding.status))).all())
    by_rule = dict((await db.execute(select(RiskFinding.rule_code, func.count())
                                     .where(RiskFinding.status != "RESOLVED").group_by(RiskFinding.rule_code))).all())
    by_source = dict((await db.execute(select(RiskFinding.source, func.count()).group_by(RiskFinding.source))).all())
    total = sum(by_status.values())

    day_col = func.to_char(func.timezone("UTC", RiskFinding.first_seen), "YYYY-MM-DD")
    per_day: Dict[str, Dict[str, int]] = {d: {} for d in _days(days, now)}
    for day, sev, n in (await db.execute(select(day_col, RiskFinding.severity, func.count())
                                         .where(RiskFinding.first_seen >= since).group_by(day_col, RiskFinding.severity))).all():
        if day in per_day:
            per_day[day][sev] = n

    risk_day = func.to_char(func.timezone("UTC", RiskEvent.evaluated_at), "YYYY-MM-DD")
    levels = {lv: 0 for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")} | dict((await db.execute(
        select(RiskEvent.risk_level, func.count()).where(RiskEvent.evaluated_at >= since)
        .group_by(RiskEvent.risk_level))).all())
    access_day: Dict[str, Dict[str, int]] = {d: {} for d in _days(days, now)}
    for day, lv, n in (await db.execute(select(risk_day, RiskEvent.risk_level, func.count())
                                        .where(RiskEvent.evaluated_at >= since).group_by(risk_day, RiskEvent.risk_level))).all():
        if day in access_day:
            access_day[day][lv] = n

    last = await db.get(AppSetting, "risk.last_evaluated_at")
    return RiskSummary(
        window_days=days, open_by_severity=open_by, by_status=by_status, by_rule=by_rule, by_source=by_source,
        new_findings_per_day=[DayPoint(day=d, counts=c) for d, c in per_day.items()],
        access_risk_by_level=levels, access_risk_per_day=[DayPoint(day=d, counts=c) for d, c in access_day.items()],
        total_findings=total, last_evaluated_at=last.value if last else None,
        rules={k: v[0] for k, v in risk_detector.RULES.items()}, thresholds=await risk_detector.thresholds(db),
    )


@router.get("/findings", response_model=PaginatedResponse[FindingOut])
async def list_findings(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    severity: Optional[str] = Query(None), status_: Optional[str] = Query(None, alias="status"),
    rule: Optional[str] = Query(None, max_length=64), source: Optional[str] = Query(None, max_length=64),
    asset_id: Optional[uuid.UUID] = None, application_id: Optional[uuid.UUID] = None,
    days: Optional[int] = Query(None, ge=1, le=365), search: Optional[str] = Query(None, max_length=100),
    db: AsyncSession = Depends(get_db), _: User = Depends(PermissionChecker("risk", "read")),
):
    q = select(RiskFinding)
    if severity:
        q = q.where(RiskFinding.severity.in_([s for s in severity.split(",") if s in SEVERITIES]))
    if status_:
        q = q.where(RiskFinding.status.in_([s for s in status_.split(",") if s in STATUSES]))
    if rule:
        q = q.where(RiskFinding.rule_code == rule)
    if source:
        q = q.where(RiskFinding.source == source)
    if asset_id:
        q = q.where(RiskFinding.asset_id == asset_id)
    if application_id:
        q = q.where(RiskFinding.application_id == application_id)
    if days:
        q = q.where(RiskFinding.last_seen >= datetime.now(timezone.utc) - timedelta(days=days))
    if search:
        like = f"%{search.strip()}%"
        q = q.where(or_(RiskFinding.title.ilike(like), RiskFinding.subject.ilike(like)))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await db.execute(q.order_by(case((RiskFinding.status == "RESOLVED", 1), else_=0), _SEV_RANK,
                                        RiskFinding.last_seen.desc()).limit(page_size).offset((page - 1) * page_size))).scalars().all()
    return PaginatedResponse[FindingOut](items=[FindingOut.model_validate(r) for r in rows], total=total, page=page,
                                         page_size=page_size, pages=(total + page_size - 1) // page_size if total else 0)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db),
                      _: User = Depends(PermissionChecker("risk", "read"))):
    f = await db.get(RiskFinding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    refs = [str(r) for r in (f.evidence or {}).get("references", [])]
    audit = {a.event_id: a for a in (await db.execute(select(AuditLog).where(AuditLog.event_id.in_(refs)))).scalars()} if refs else {}
    events = [EvidenceEvent(reference=r, found=r in audit,
                            **({"timestamp": audit[r].timestamp, "action": audit[r].action, "actor": audit[r].actor_username,
                                "result": audit[r].result, "session_id": audit[r].session_id} if r in audit else {}))
              for r in refs]
    asset = await db.get(Asset, f.asset_id) if f.asset_id else None
    app = await db.get(Application, f.application_id) if f.application_id else None
    user = await db.get(User, f.user_id) if f.user_id else None
    return FindingDetail(**FindingOut.model_validate(f).model_dump(), asset_name=asset.name if asset else None,
                         application_name=app.name if app else None, username=user.username if user else None,
                         evidence_events=events)


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]
    note: Optional[str] = Field(default=None, max_length=500)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding(finding_id: uuid.UUID, body: FindingUpdate, request: Request,
                         db: AsyncSession = Depends(get_db), actor: User = Depends(PermissionChecker("risk", "manage"))):
    f = await db.get(RiskFinding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    before = f.status
    f.status, f.status_note = body.status, body.note
    f.status_changed_at, f.status_changed_by = datetime.now(timezone.utc), actor.id
    await write_audit_log(db, actor=actor, action="RISK_FINDING_UPDATED", target_type="risk_finding",
                          target_id=str(f.id), source_ip=client_ip(request), severity="MEDIUM",
                          metadata={"before": before, "after": body.status, "rule": f.rule_code, "note": body.note})
    await db.commit()
    await db.refresh(f)
    return f


@router.post("/evaluate")
async def evaluate_now(request: Request, db: AsyncSession = Depends(get_db),
                       actor: User = Depends(PermissionChecker("risk", "manage"))):
    stats = await risk_detector.evaluate(db)
    await write_audit_log(db, actor=actor, action="RISK_EVALUATED_MANUALLY", target_type="risk",
                          source_ip=client_ip(request), metadata=stats)
    await db.commit()
    return stats


class IngestFinding(BaseModel):
    """Contract for an EXTERNAL source (vulnerability scanner, SIEM correlation, ...)."""
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    external_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=4000)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    remediation: str = Field(min_length=1, max_length=4000)
    observed_at: datetime
    asset_id: Optional[uuid.UUID] = None
    application_id: Optional[uuid.UUID] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)


@router.post("/findings/ingest", response_model=FindingOut, status_code=status.HTTP_201_CREATED)
async def ingest_finding(body: IngestFinding, request: Request, db: AsyncSession = Depends(get_db),
                         actor: User = Depends(PermissionChecker("risk", "manage"))):
    if body.source == risk_detector.SOURCE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "This source name is reserved for the built-in detector.")
    if body.asset_id and await db.get(Asset, body.asset_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown asset_id")
    if body.application_id and await db.get(Application, body.application_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown application_id")
    fp = risk_detector._fp("EXTERNAL", body.source, body.external_id)
    f = (await db.execute(select(RiskFinding).where(RiskFinding.fingerprint == fp))).scalar_one_or_none()
    observed = body.observed_at if body.observed_at.tzinfo else body.observed_at.replace(tzinfo=timezone.utc)
    if f is None:
        f = RiskFinding(fingerprint=fp, rule_code="EXTERNAL", source=body.source, status="OPEN", first_seen=observed,
                        last_seen=observed, occurrences=0, subject="", evidence={}, title="", description="",
                        remediation="", severity=body.severity)
        db.add(f)
    f.title, f.description, f.severity, f.remediation = body.title, body.description, body.severity, body.remediation
    f.asset_id, f.application_id = body.asset_id, body.application_id
    asset = await db.get(Asset, body.asset_id) if body.asset_id else None
    app = await db.get(Application, body.application_id) if body.application_id else None
    f.subject = (asset.name if asset else app.name if app else body.external_id)[:255]
    f.evidence = {"external_id": body.external_id, **body.evidence}
    f.first_seen, f.last_seen = min(f.first_seen, observed), max(f.last_seen, observed)
    f.occurrences = (f.occurrences or 0) + 1
    await write_audit_log(db, actor=actor, action="RISK_FINDING_INGESTED", target_type="risk_finding",
                          source_ip=client_ip(request), metadata={"source": body.source, "external_id": body.external_id,
                                                                   "severity": body.severity})
    await db.commit()
    await db.refresh(f)
    return f


class RiskThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mfa_failure_threshold: int = Field(ge=1, le=50)
    launch_denial_threshold: int = Field(ge=1, le=100)


@router.put("/thresholds", response_model=RiskThresholds)
async def set_thresholds(body: RiskThresholds, request: Request, db: AsyncSession = Depends(get_db),
                         actor: User = Depends(PermissionChecker("risk", "manage"))):
    before = await risk_detector.thresholds(db)
    for key, value in (("risk.mfa_failure_threshold", body.mfa_failure_threshold),
                       ("risk.launch_denial_threshold", body.launch_denial_threshold)):
        row = await db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value, updated_by=actor.id))
        else:
            row.value, row.updated_by = value, actor.id
    await write_audit_log(db, actor=actor, action="RISK_THRESHOLDS_CHANGED", target_type="settings",
                          source_ip=client_ip(request), severity="MEDIUM",
                          metadata={"before": before, "after": body.model_dump()})
    await db.commit()
    return body
