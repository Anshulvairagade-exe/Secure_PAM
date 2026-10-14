"""
Integrated asset + credential workflow (ADMIN: assets:create / vault:manage).

  GET  /credential-provisioning/status     is provisioning configured? approved references, bindings, OpenBao UI link
  POST /credential-provisioning/assets     create an asset AND provision its credential, one transaction
  PUT  /assets/{asset_id}/credential       provision/rotate the credential of an existing asset (also the retry path)

The browser sends a secret NAME from the approved list plus username/password over TLS; it never sends a
path or receives a token or stored value. The password is a SecretStr, is never echoed in a response,
log, validation error or audit row. See app.services.credential_provisioning for the write/verify/bind
sequence and its fail-closed behaviour.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db
from app.models.asset import Asset
from app.models.user import User
from app.schemas.assets import AssetCreate, AssetOut
from app.secret_providers.paths import validate_secret_name
from app.secret_providers.writer import writer_status
from app.services.credential_provisioning import (
    ProvisioningError,
    allowed_secret_names,
    bound_assets,
    provision,
)

router = APIRouter(tags=["Asset credentials"])


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=255)
    password: SecretStr = Field(min_length=1, max_length=4096)
    secret_type: str = Field(default="PASSWORD", pattern="^(PASSWORD|SSH_KEY)$")

    @field_validator("secret_name")
    @classmethod
    def safe_name(cls, v: str) -> str:
        try:
            return validate_secret_name(v)
        except Exception:
            raise ValueError("secret_name must be one approved reference name")


class AssetWithCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset: AssetCreate
    credential: CredentialInput


class ReferenceStatus(BaseModel):
    name: str
    path: str
    bound_asset_id: Optional[UUID]
    bound_asset_name: Optional[str]


class ProvisioningStatus(BaseModel):
    configured: bool
    reason: str
    secret_provider: str
    references: List[ReferenceStatus]
    openbao_ui_url: Optional[str]


class ProvisionedCredential(BaseModel):
    asset: AssetOut
    vault_path: str
    version: int
    username: str
    verified: bool = True


def _error(exc: ProvisioningError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content=exc.body())


@router.get("/credential-provisioning/status", response_model=ProvisioningStatus)
async def provisioning_status(db: AsyncSession = Depends(get_db),
                              _: User = Depends(PermissionChecker("vault", "manage"))):
    configured, reason = writer_status()
    bound = await bound_assets(db)
    names = {a.id: a.name for a in (await db.execute(
        select(Asset).where(Asset.id.in_(list(bound.values())), Asset.is_deleted == False)  # noqa: E712
    )).scalars().all()} if bound else {}
    refs = [ReferenceStatus(name=n, path=f"{settings.OPENBAO_SECRET_PATH_PREFIX}/assets/{n}",
                            bound_asset_id=bound.get(n), bound_asset_name=names.get(bound.get(n)))
            for n in allowed_secret_names()]
    return ProvisioningStatus(configured=configured, reason=reason, secret_provider=settings.SECRET_PROVIDER,
                              references=refs, openbao_ui_url=settings.OPENBAO_UI_URL or None)


async def _audit(db, request, actor, *, asset_id, result, severity, **meta):
    await write_audit_log(db, actor=actor, action="CREDENTIAL_PROVISIONED", target_type="asset",
                          target_id=str(asset_id) if asset_id else None, source_ip=client_ip(request),
                          result=result, severity=severity, metadata=meta)


@router.post("/credential-provisioning/assets", response_model=ProvisionedCredential,
             status_code=status.HTTP_201_CREATED)
async def create_asset_with_credential(
    body: AssetWithCredential, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("vault", "manage")),
):
    """Create the asset and provision its credential atomically: the asset row is committed only if the
    credential was written AND verified AND bound. Requires vault:manage (ADMIN), which implies the
    asset-creation right for this combined action."""
    cred = body.credential
    configured, reason = writer_status()
    if not configured:  # decided before anything is created
        exc = ProvisioningError("configure", "PROVISIONING_NOT_CONFIGURED", reason,
                                "Create the asset without a credential, or deploy the writer identity first.", 503)
        await _audit(db, request, actor, asset_id=None, result="FAILURE", severity="MEDIUM",
                     stage=exc.stage, error_code=exc.code, secret_name=cred.secret_name, asset_name=body.asset.name)
        await db.commit()
        return _error(exc)

    savepoint = await db.begin_nested()  # asset + binding roll back together; the actor stays loaded
    asset = Asset(**body.asset.model_dump(), created_by=actor.id, updated_by=actor.id)
    db.add(asset)
    await db.flush()
    try:
        result = await provision(db, asset_id=asset.id, secret_name=cred.secret_name, username=cred.username,
                                 secret=cred.password.get_secret_value(), secret_type=cred.secret_type)
    except ProvisioningError as exc:
        await savepoint.rollback()  # no asset, no binding
        await _audit(db, request, actor, asset_id=None, result="FAILURE", severity="HIGH", stage=exc.stage,
                     error_code=exc.code, secret_name=cred.secret_name, asset_name=body.asset.name,
                     written_version=exc.written_version)
        await db.commit()
        return _error(exc)
    await savepoint.commit()
    await write_audit_log(db, actor=actor, action="ASSET_CREATED", target_type="asset", target_id=str(asset.id),
                          source_ip=client_ip(request),
                          metadata={"name": asset.name, "asset_type": asset.asset_type, "with_credential": True})
    await _audit(db, request, actor, asset_id=asset.id, result="SUCCESS", severity="HIGH",
                 secret_reference=result.path, version=result.version, secret_type=cred.secret_type,
                 verified=True)
    await db.commit()
    await db.refresh(asset)
    return ProvisionedCredential(asset=AssetOut.model_validate(asset), vault_path=result.path,
                                 version=result.version, username=cred.username)


@router.put("/assets/{asset_id}/credential", response_model=ProvisionedCredential)
async def set_asset_credential(
    asset_id: UUID, body: CredentialInput, request: Request, db: AsyncSession = Depends(get_db),
    actor: User = Depends(PermissionChecker("vault", "manage")),
):
    """Provision or rotate the credential of an existing asset (also the retry after a partial failure)."""
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id, Asset.is_deleted == False))).scalar_one_or_none()  # noqa: E712
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    savepoint = await db.begin_nested()
    try:
        result = await provision(db, asset_id=asset.id, secret_name=body.secret_name, username=body.username,
                                 secret=body.password.get_secret_value(), secret_type=body.secret_type)
    except ProvisioningError as exc:
        await savepoint.rollback()  # the previous binding stays active
        await _audit(db, request, actor, asset_id=asset_id, result="FAILURE", severity="HIGH", stage=exc.stage,
                     error_code=exc.code, secret_name=body.secret_name, written_version=exc.written_version)
        await db.commit()
        return _error(exc)
    await savepoint.commit()
    await _audit(db, request, actor, asset_id=asset.id, result="SUCCESS", severity="HIGH",
                 secret_reference=result.path, version=result.version, secret_type=body.secret_type, verified=True)
    await db.commit()
    await db.refresh(asset)
    return ProvisionedCredential(asset=AssetOut.model_validate(asset), vault_path=result.path,
                                 version=result.version, username=body.username)
