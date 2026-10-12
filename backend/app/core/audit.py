"""
Reusable audit-event writer.

Every privileged administrative action (Asset/Application/Policy
create/update/delete, and permission denials) must produce an AuditLog
row — see app/models/audit.py. NEVER pass secrets/passwords/tokens into
`metadata`; it's stored as-is and may surface in the audit UI/SIEM export.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_event_id
from app.models.audit import AuditLog
from app.models.user import User


async def write_audit_log(
    db: AsyncSession,
    *,
    actor: Optional[User],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    request_id: Optional[UUID] = None,
    session_id: Optional[UUID] = None,
    source_ip: Optional[str] = None,
    result: str = "SUCCESS",
    severity: str = "INFO",
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Insert one audit event and flush it (so constraint errors surface
    immediately), but deliberately do NOT commit — that's the caller's
    responsibility.

    This matters most on a denial path: `get_db` rolls back the whole
    session when an exception propagates out of the request (e.g. the
    HTTPException a PermissionChecker raises right after calling this).
    If that denial audit row were left uncommitted, logging the denial
    would silently undo itself. Callers that write an audit entry and
    then raise MUST `await db.commit()` first — see
    app.core.deps.PermissionChecker for the pattern.
    """
    entry = AuditLog(
        event_id=generate_event_id(),
        timestamp=datetime.now(timezone.utc),
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else "anonymous",
        action=action,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        session_id=session_id,
        source_ip=source_ip,
        result=result,
        severity=severity,
        details=metadata,
    )
    db.add(entry)
    await db.flush()
    return entry


def client_ip(request) -> Optional[str]:
    """Best-effort source IP extraction for audit events."""
    return request.client.host if request and request.client else None
