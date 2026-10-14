"""
User and role administration (read-mostly).

Users come from the identity provider (or DEV_MODE accounts); SecurePAM's
own `roles`/`user_roles` tables decide what they may do. A token's claimed
roles are never consulted here or anywhere else for authorization, so the
roles shown are SecurePAM application roles only.

Reads need users:read; changes need users:update (ADMIN). Changes are
audited with before/after values, refuse self-modification, and never
remove the last active administrator. Responses never contain password
hashes, tokens or secrets.
"""

import uuid
from datetime import datetime
from typing import List, Optional

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.security import hash_password
from app.core.deps import PermissionChecker, get_db
from app.models.role import Role
from app.models.session import Session
from app.models.user import User, UserRole
from app.schemas.common import PaginatedResponse
from app.services.session_policy import count_slots

router = APIRouter(tags=["Users & Roles"])

LIVE_SESSION_STATUSES = {"CREATED", "STARTING", "ACTIVE"}
_SORTABLE = {"username": User.username, "last_login": User.last_login, "created_at": User.created_at}


class RoleRef(BaseModel):
    id: uuid.UUID
    name: str


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    full_name: str
    email: str
    is_active: bool
    is_system_user: bool
    mfa_enabled: bool
    external_id: Optional[str]
    identity_source: str
    roles: List[RoleRef]
    last_login: Optional[datetime]
    created_at: datetime
    active_sessions: int = 0


class UserDetail(UserOut):
    last_login_ip: Optional[str]
    failed_login_count: int
    permissions: List[str]
    live_sessions: int


class PermissionOut(BaseModel):
    name: str
    description: Optional[str]


class RoleUser(BaseModel):
    id: uuid.UUID
    username: str
    is_active: bool


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    is_system: bool
    is_active: bool
    permissions: List[PermissionOut]
    users: List[RoleUser]


_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class UserCreate(BaseModel):
    """DEV_MODE: a local development account (password required). Keycloak mode: pre-register the
    person's Keycloak subject ID (external_id), which is the only identity the backend accepts; no
    password here (it lives in Keycloak)."""
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=64)
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    external_id: Optional[str] = Field(default=None, max_length=36)
    password: Optional[SecretStr] = Field(default=None, min_length=12, max_length=256)
    role_ids: List[uuid.UUID] = Field(default_factory=list, max_length=10)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip().lower()
        if not _USERNAME_RE.match(v):
            raise ValueError("username: lowercase letters, digits, dot, dash, underscore")
        return v

    @field_validator("external_id")
    @classmethod
    def _external(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _UUID_RE.match(v.strip().lower()):
            raise ValueError("external_id must be the Keycloak user ID (UUID)")
        return v.strip().lower() if v else None


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    external_id: Optional[str] = Field(default=None, max_length=36)

    @field_validator("external_id")
    @classmethod
    def _external(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _UUID_RE.match(v.strip().lower()):
            raise ValueError("external_id must be the Keycloak user ID (UUID)")
        return v.strip().lower() if v else None


class AssignRole(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_id: uuid.UUID


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id, username=user.username, full_name=user.full_name, email=user.email,
        is_active=user.is_active, is_system_user=user.is_system_user, mfa_enabled=user.mfa_enabled,
        external_id=user.external_id,
        # Derived; the hash itself is never exposed.
        identity_source="development account" if user.hashed_password else "identity provider",
        roles=[RoleRef(id=ur.role.id, name=ur.role.name) for ur in user.roles if ur.role],
        last_login=user.last_login, created_at=user.created_at,
    )


async def _live_sessions(db: AsyncSession, user_id: uuid.UUID) -> int:
    return (await db.execute(
        select(func.count()).select_from(Session).where(
            Session.user_id == user_id, Session.status.in_(LIVE_SESSION_STATUSES))
    )).scalar_one()


async def _get_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None or user.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


def _is_active_admin(user: User) -> bool:
    return user.is_active and any(ur.role and ur.role.name == "ADMIN" and ur.role.is_active for ur in user.roles)


async def _other_active_admins(db: AsyncSession, excluding: uuid.UUID) -> int:
    users = (await db.execute(
        select(User).where(User.is_deleted == False, User.id != excluding)  # noqa: E712
    )).scalars().all()
    return sum(1 for u in users if _is_active_admin(u))


def _refuse_self(actor: User, target: User, what: str) -> None:
    if actor.id == target.id:
        raise HTTPException(status.HTTP_409_CONFLICT, f"You cannot {what} your own account.")


async def _audit(db, request, actor, action, target, **metadata):
    await write_audit_log(
        db, actor=actor, action=action, target_type="user", target_id=str(target.id),
        source_ip=client_ip(request), result="SUCCESS", severity="HIGH",
        metadata={"username": target.username, **metadata},
    )


@router.get("/users", response_model=PaginatedResponse[UserOut])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    search: Optional[str] = Query(None, max_length=100),
    active: Optional[bool] = None,
    role: Optional[str] = Query(None, max_length=50),
    sort_by: str = Query("username"),
    sort_order: str = Query("asc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("users", "read")),
):
    query = select(User).where(User.is_deleted == False)  # noqa: E712
    if search:
        like = f"%{search.strip()}%"
        query = query.where(or_(User.username.ilike(like), User.email.ilike(like), User.full_name.ilike(like)))
    if active is not None:
        query = query.where(User.is_active == active)
    if role:
        query = query.where(User.id.in_(
            select(UserRole.user_id).join(Role, Role.id == UserRole.role_id).where(Role.name == role)))
    column = _SORTABLE.get(sort_by, User.username)
    query = query.order_by(column.desc() if sort_order == "desc" else column.asc(), User.username)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.limit(page_size).offset((page - 1) * page_size))).scalars().all()
    items = [_user_out(u) for u in rows]
    for item in items:
        item.active_sessions = await count_slots(db, item.id)
    return PaginatedResponse[UserOut](
        items=items, total=total, page=page, page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


async def _ensure_unique(db: AsyncSession, *, username=None, email=None, external_id=None, exclude=None):
    for column, value, label in ((User.username, username, "username"), (User.email, email, "email"),
                                 (User.external_id, external_id, "Keycloak user ID")):
        if value is None:
            continue
        q = select(User.id).where(column == value)
        if exclude is not None:
            q = q.where(User.id != exclude)
        if (await db.execute(q)).first():
            raise HTTPException(status.HTTP_409_CONFLICT, f"Another account already has this {label}.")


def _local_accounts() -> bool:
    """DEV_MODE signs users in by username with a local password; otherwise Keycloak (by subject ID)."""
    return settings.DEV_MODE


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, request: Request, db: AsyncSession = Depends(get_db),
                      actor: User = Depends(PermissionChecker("users", "create"))):
    if _local_accounts():
        if body.password is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "Development accounts need an initial password (at least 12 characters).")
    else:
        if body.password is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "Passwords are managed in Keycloak; register the user's Keycloak ID instead.")
        if not body.external_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "external_id (the user's Keycloak ID) is required: it is how sign-in is matched.")
    await _ensure_unique(db, username=body.username, email=str(body.email), external_id=body.external_id)
    roles = []
    for rid in dict.fromkeys(body.role_ids):
        role = await db.get(Role, rid)
        if role is None or not role.is_active:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown or inactive role.")
        roles.append(role)
    user = User(username=body.username, email=str(body.email), full_name=body.full_name,
                external_id=body.external_id, is_active=True,
                hashed_password=hash_password(body.password.get_secret_value()) if body.password else None)
    db.add(user)
    await db.flush()
    for role in roles:
        db.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=actor.id))
    await _audit(db, request, actor, "USER_CREATED", user, roles=[r.name for r in roles],
                 identity_source="development account" if body.password else "identity provider",
                 external_id_set=bool(body.external_id))
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: uuid.UUID, body: UserUpdate, request: Request, db: AsyncSession = Depends(get_db),
                      actor: User = Depends(PermissionChecker("users", "update"))):
    user = await _get_user(db, user_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        return _user_out(user)
    if "external_id" in changes:
        _refuse_self(actor, user, "relink the identity of")
        if user.external_id and user.external_id != changes["external_id"]:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "This account is already linked to a Keycloak identity; deactivate it and create a new one instead.")
    if "email" in changes:
        changes["email"] = str(changes["email"])
    await _ensure_unique(db, email=changes.get("email"), external_id=changes.get("external_id"), exclude=user.id)
    before = {k: getattr(user, k) for k in changes}
    for k, v in changes.items():
        setattr(user, k, v)
    await _audit(db, request, actor, "USER_UPDATED", user, changed_fields=sorted(changes),
                 before={k: v for k, v in before.items() if k != "external_id"})
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.get("/users/{user_id}", response_model=UserDetail)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("users", "read")),
):
    user = await _get_user(db, user_id)
    perms = sorted({p.name for ur in user.roles if ur.role and ur.role.is_active for p in ur.role.permissions})
    return UserDetail(
        **_user_out(user).model_dump(), last_login_ip=user.last_login_ip,
        failed_login_count=user.failed_login_count, permissions=perms,
        live_sessions=await _live_sessions(db, user.id),
    )


@router.post("/users/{user_id}/deactivate", response_model=UserOut)
async def deactivate_user(
    user_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("users", "update")),
):
    """Disable sign-in. The SSH gateway re-reads the user every second, so
    live sessions are torn down, not merely hidden."""
    user = await _get_user(db, user_id)
    _refuse_self(actor, user, "deactivate")
    if user.is_system_user:
        raise HTTPException(status.HTTP_409_CONFLICT, "System accounts cannot be deactivated.")
    if _is_active_admin(user) and await _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "This is the last active administrator.")
    if user.is_active:
        live = await _live_sessions(db, user.id)
        user.is_active = False
        await _audit(db, request, actor, "USER_DEACTIVATED", user, live_sessions_affected=live)
        await db.commit()
    return _user_out(user)


@router.post("/users/{user_id}/reactivate", response_model=UserOut)
async def reactivate_user(
    user_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("users", "update")),
):
    user = await _get_user(db, user_id)
    if not user.is_active:
        user.is_active = True
        await _audit(db, request, actor, "USER_REACTIVATED", user)
        await db.commit()
    return _user_out(user)


@router.post("/users/{user_id}/roles", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def assign_role(
    user_id: uuid.UUID, body: AssignRole, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("users", "update")),
):
    user = await _get_user(db, user_id)
    _refuse_self(actor, user, "change the roles of")
    role = await db.get(Role, body.role_id)
    if role is None or not role.is_active:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown or inactive role.")
    if any(ur.role_id == role.id for ur in user.roles):
        raise HTTPException(status.HTTP_409_CONFLICT, "The user already has this role.")
    before = sorted(ur.role.name for ur in user.roles if ur.role)
    db.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=actor.id))
    await _audit(db, request, actor, "ROLE_ASSIGNED", user, role=role.name, roles_before=before)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.delete("/users/{user_id}/roles/{role_id}", response_model=UserOut)
async def remove_role(
    user_id: uuid.UUID, role_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("users", "update")),
):
    user = await _get_user(db, user_id)
    _refuse_self(actor, user, "change the roles of")
    link = next((ur for ur in user.roles if ur.role_id == role_id), None)
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "The user does not have this role.")
    if link.role.name == "ADMIN" and _is_active_admin(user) and await _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "This is the last active administrator.")
    before = sorted(ur.role.name for ur in user.roles if ur.role)
    role_name = link.role.name
    await db.delete(link)
    await _audit(db, request, actor, "ROLE_REMOVED", user, role=role_name, roles_before=before)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.get("/roles", response_model=List[RoleOut])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("users", "read")),
):
    """SecurePAM application roles with their permissions and assigned users.
    Identity-provider roles are not shown: they carry no authority here."""
    roles = (await db.execute(select(Role).order_by(Role.name))).scalars().all()
    links = (await db.execute(
        select(UserRole.role_id, User).join(User, User.id == UserRole.user_id).where(User.is_deleted == False)  # noqa: E712
        .order_by(User.username)
    )).all()
    by_role: dict = {}
    for role_id, user in links:
        by_role.setdefault(role_id, []).append(RoleUser(id=user.id, username=user.username, is_active=user.is_active))
    return [
        RoleOut(
            id=r.id, name=r.name, description=r.description, is_system=r.is_system, is_active=r.is_active,
            permissions=[PermissionOut(name=p.name, description=p.description)
                         for p in sorted(r.permissions, key=lambda p: p.name)],
            users=by_role.get(r.id, []),
        )
        for r in roles
    ]
