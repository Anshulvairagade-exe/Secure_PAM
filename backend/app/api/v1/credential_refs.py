"""
Credential reference management for registered assets and applications.

Manages the vault_refs row that says WHERE an asset's credential lives —
never the credential itself. Nothing here reads the secret store, and no
response includes a secret value. Retrieval happens only in-process via
app.services.credential_service for an authorized session.

Admin-only (vault:read / vault:manage). The reference path is derived
server-side from a single validated name, so a client can never point a
reference at an arbitrary location in OpenBao.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db
from app.models.application import Application
from app.models.asset import Asset
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.schemas.credential_refs import ApplicationCredentialRefOut, CredentialRefOut, CredentialRefSet
from app.secret_providers.paths import asset_secret_path

router = APIRouter(prefix="/assets", tags=["credential-refs"])
application_router = APIRouter(prefix="/applications", tags=["credential-refs"])


async def _get_asset_or_404(db: AsyncSession, asset_id: UUID) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id, Asset.is_deleted == False))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


async def _active_ref(db: AsyncSession, asset_id: UUID):
    result = await db.execute(
        select(VaultRef).where(VaultRef.asset_id == asset_id, VaultRef.is_active == True)
    )
    return result.scalars().first()


@router.get("/{asset_id}/credential-ref", response_model=CredentialRefOut)
async def get_credential_ref(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("vault", "read")),
):
    await _get_asset_or_404(db, asset_id)
    ref = await _active_ref(db, asset_id)
    if not ref:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No credential reference for this asset")
    return ref


@router.put("/{asset_id}/credential-ref", response_model=CredentialRefOut)
async def set_credential_ref(
    asset_id: UUID,
    payload: CredentialRefSet,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    """Point the asset at <prefix>/assets/<secret_name> in the configured
    provider. Any previously active reference is deactivated (kept for
    history), so an asset always has at most one active reference."""
    await _get_asset_or_404(db, asset_id)
    path = asset_secret_path(settings.OPENBAO_SECRET_PATH_PREFIX, payload.secret_name)

    await db.execute(
        update(VaultRef).where(VaultRef.asset_id == asset_id, VaultRef.is_active == True).values(is_active=False)
    )
    ref = VaultRef(
        asset_id=asset_id,
        provider=settings.SECRET_PROVIDER,
        vault_path=path,
        secret_type=payload.secret_type,
        username=payload.username,
        secret_version=payload.secret_version,
        is_active=True,
    )
    db.add(ref)
    await db.flush()

    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_SET", target_type="asset", target_id=str(asset_id),
        source_ip=client_ip(request), result="SUCCESS", severity="MEDIUM",
        metadata={
            "vault_ref_id": str(ref.id), "provider": ref.provider, "secret_reference": path,
            "secret_type": ref.secret_type, "secret_version": ref.secret_version,
        },
    )
    await db.commit()
    await db.refresh(ref)
    return ref


@router.delete("/{asset_id}/credential-ref", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_credential_ref(
    asset_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    await _get_asset_or_404(db, asset_id)
    ref = await _active_ref(db, asset_id)
    if not ref:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No credential reference for this asset")
    ref.is_active = False
    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_DEACTIVATED", target_type="asset",
        target_id=str(asset_id), source_ip=client_ip(request), result="SUCCESS", severity="MEDIUM",
        metadata={"vault_ref_id": str(ref.id), "secret_reference": ref.vault_path},
    )
    await db.commit()


class CredentialRefCheck(BaseModel):
    """Whether the referenced secret can be read by the backend's own
    restricted identity. Never contains the secret."""
    status: str  # ok, secret_not_found, access_denied, unavailable, malformed, no_reference
    message: str


_CHECK_RESULTS = {
    "ok": "The secret exists and the gateway can read it.",
    "secret_not_found": "No secret exists at this reference. Store the secret in OpenBao at this path.",
    "access_denied": "The gateway's secret-store identity is not permitted to read this path.",
    "unavailable": "The secret store is unreachable.",
    "malformed": "The secret exists but has no field for its secret type (for example, no password).",
    "no_reference": "This asset has no active credential reference.",
}


async def _check_reference(ref) -> str:
    """Read the referenced secret with the backend's restricted runtime identity and discard it at
    once. Fails closed: any provider, TLS or authentication problem is reported, never bypassed."""
    from app.secret_providers import (
        MalformedSecretError,
        SecretAccessDeniedError,
        SecretNotFoundError,
        SecretProviderError,
        SecretProviderUnavailableError,
        get_secret_provider,
    )
    from app.services.credential_service import SECRET_FIELDS

    if ref is None:
        return "no_reference"
    try:
        record = await get_secret_provider().read_secret(ref.vault_path, version=ref.secret_version)
        field = SECRET_FIELDS.get(ref.secret_type)
        has_field = bool(field and isinstance(record.data.get(field), str) and record.data.get(field))
        del record
        return "ok" if has_field else "malformed"
    except SecretNotFoundError:
        return "secret_not_found"
    except SecretAccessDeniedError:
        return "access_denied"
    except SecretProviderUnavailableError:
        return "unavailable"
    except MalformedSecretError:
        return "malformed"
    except SecretProviderError:
        return "unavailable"


@router.post("/{asset_id}/credential-ref/check", response_model=CredentialRefCheck)
async def check_credential_ref(
    asset_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    """Read the referenced secret with the backend's restricted runtime
    identity and discard it, to report whether checkout would work."""
    await _get_asset_or_404(db, asset_id)
    ref = await _active_ref(db, asset_id)
    result = await _check_reference(ref)

    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_CHECKED", target_type="asset", target_id=str(asset_id),
        source_ip=client_ip(request), result="SUCCESS" if result == "ok" else "FAILURE",
        severity="INFO" if result == "ok" else "MEDIUM",
        metadata={"result": result, "secret_reference": ref.vault_path if ref else None},
    )
    await db.commit()
    return CredentialRefCheck(status=result, message=_CHECK_RESULTS[result])


# --- Applications --------------------------------------------------------------------------------
# An application (e.g. the Wazuh dashboard opened in the isolated browser) can be bound to ONE
# allowlisted secret name (settings.APPLICATION_CREDENTIAL_SECRET_NAMES), resolving server-side to
# <prefix>/assets/<name>. The binding records where the credential lives for the operator runbook and
# the readiness check below. Web sessions never check it out: the operator signs in manually.


async def _get_application_or_404(db: AsyncSession, application_id: UUID) -> Application:
    result = await db.execute(
        select(Application).where(Application.id == application_id, Application.is_deleted == False)
    )
    application = result.scalar_one_or_none()
    if not application:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return application


async def _active_application_ref(db: AsyncSession, application_id: UUID):
    result = await db.execute(
        select(VaultRef).where(VaultRef.application_id == application_id, VaultRef.is_active == True)
    )
    return result.scalars().first()


@application_router.get("/{application_id}/credential-ref", response_model=ApplicationCredentialRefOut)
async def get_application_credential_ref(
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("vault", "read")),
):
    await _get_application_or_404(db, application_id)
    ref = await _active_application_ref(db, application_id)
    if not ref:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No credential reference for this application")
    return ref


@application_router.put("/{application_id}/credential-ref", response_model=ApplicationCredentialRefOut)
async def set_application_credential_ref(
    application_id: UUID,
    payload: CredentialRefSet,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    """Bind the application to an ALLOWLISTED secret name. Anything else is refused (and audited),
    and a name already bound to another application is refused: one credential, one application."""
    await _get_application_or_404(db, application_id)
    source_ip = client_ip(request)
    allowed = set(settings.APPLICATION_CREDENTIAL_SECRET_NAMES)

    async def refuse(code: int, reason: str, detail: str):
        await write_audit_log(
            db, actor=current_user, action="CREDENTIAL_REF_SET", target_type="application",
            target_id=str(application_id), source_ip=source_ip, result="DENIED", severity="MEDIUM",
            metadata={"reason": reason, "requested_secret_name": payload.secret_name},
        )
        await db.commit()
        raise HTTPException(code, detail)

    if payload.secret_name not in allowed:
        await refuse(status.HTTP_422_UNPROCESSABLE_ENTITY, "SECRET_NAME_NOT_ALLOWLISTED",
                     f"secret_name must be one of the registered application credentials: {sorted(allowed)}")
    path = asset_secret_path(settings.OPENBAO_SECRET_PATH_PREFIX, payload.secret_name)
    other = await db.execute(
        select(VaultRef).where(VaultRef.vault_path == path, VaultRef.is_active == True,
                               VaultRef.application_id != application_id)
    )
    if other.scalars().first() is not None:
        await refuse(status.HTTP_409_CONFLICT, "SECRET_ALREADY_BOUND",
                     "This credential reference is already bound to another application.")

    await db.execute(
        update(VaultRef).where(VaultRef.application_id == application_id, VaultRef.is_active == True)
        .values(is_active=False)
    )
    ref = VaultRef(
        application_id=application_id,
        provider=settings.SECRET_PROVIDER,
        vault_path=path,
        secret_type=payload.secret_type,
        username=payload.username,
        secret_version=payload.secret_version,
        is_active=True,
    )
    db.add(ref)
    await db.flush()
    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_SET", target_type="application",
        target_id=str(application_id), source_ip=source_ip, result="SUCCESS", severity="MEDIUM",
        metadata={"vault_ref_id": str(ref.id), "provider": ref.provider, "secret_reference": path,
                  "secret_type": ref.secret_type, "secret_version": ref.secret_version},
    )
    await db.commit()
    await db.refresh(ref)
    return ref


@application_router.delete("/{application_id}/credential-ref", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_application_credential_ref(
    application_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    await _get_application_or_404(db, application_id)
    ref = await _active_application_ref(db, application_id)
    if not ref:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No credential reference for this application")
    ref.is_active = False
    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_DEACTIVATED", target_type="application",
        target_id=str(application_id), source_ip=client_ip(request), result="SUCCESS", severity="MEDIUM",
        metadata={"vault_ref_id": str(ref.id), "secret_reference": ref.vault_path},
    )
    await db.commit()


@application_router.post("/{application_id}/credential-ref/check", response_model=CredentialRefCheck)
async def check_application_credential_ref(
    application_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("vault", "manage")),
):
    """Whether the backend's restricted runtime identity can read the bound secret. The value is
    discarded immediately and never returned, logged or audited."""
    await _get_application_or_404(db, application_id)
    ref = await _active_application_ref(db, application_id)
    result = await _check_reference(ref)
    await write_audit_log(
        db, actor=current_user, action="CREDENTIAL_REF_CHECKED", target_type="application",
        target_id=str(application_id), source_ip=client_ip(request),
        result="SUCCESS" if result == "ok" else "FAILURE", severity="INFO" if result == "ok" else "MEDIUM",
        metadata={"result": result, "secret_reference": ref.vault_path if ref else None},
    )
    await db.commit()
    return CredentialRefCheck(status=result, message=_CHECK_RESULTS[result].replace("This asset", "This application"))
