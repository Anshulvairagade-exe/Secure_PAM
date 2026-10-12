"""
Credential retrieval for future RDP/SSH gateways.

JITService.validate is required before any provider call. A VaultRef row
is only a pointer. This service returns secret material to gateway code;
it is not an HTTP endpoint and must not be exposed to the frontend.
"""

from typing import Optional
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.logging import get_logger
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secrets.base import SecretDeniedError, SecretMaterial, SecretNotFoundError, SecretProvider
from app.secrets.openbao import get_secret_provider
from app.services.jit_service import JITService


class CredentialRetrievalService:
    def __init__(self, provider: Optional[SecretProvider] = None, jit: Optional[JITService] = None, logger=None):
        self._provider = provider if provider is not None else get_secret_provider()
        self._jit = jit or JITService()
        self._logger = logger if logger is not None else get_logger("securepam.secrets")

    async def retrieve(
        self,
        db: AsyncSession,
        *,
        user: User,
        target_id: UUID,
        protocol: str,
    ) -> SecretMaterial:
        grant = await self._jit.validate(
            db, user_id=user.id, target_id=target_id, protocol=protocol
        )
        if grant is None:
            self._logger.warning(
                "credential_retrieval_denied",
                target_id=str(target_id),
                protocol=protocol,
                error_code="denied",
            )
            await write_audit_log(
                db,
                actor=user,
                action="CREDENTIAL_RETRIEVAL_DENIED",
                target_type="vault_ref",
                target_id=str(target_id),
                result="FAILURE",
                severity="WARNING",
                metadata={"protocol": protocol, "reason": "jit_not_active"},
            )
            raise SecretDeniedError("Credential retrieval denied")

        result = await db.execute(
            select(VaultRef).where(
                VaultRef.is_active == True,
                or_(VaultRef.asset_id == target_id, VaultRef.application_id == target_id),
            )
        )
        ref = result.scalars().first()
        if ref is None:
            await write_audit_log(
                db,
                actor=user,
                action="CREDENTIAL_RETRIEVAL_FAILED",
                target_type="vault_ref",
                target_id=str(target_id),
                request_id=grant.request_id,
                result="FAILURE",
                severity="WARNING",
                metadata={"protocol": protocol, "reason": "reference_missing"},
            )
            raise SecretNotFoundError("Secret reference was not found")

        try:
            material = await self._provider.read(ref.vault_path)
        except Exception as exc:
            error_code = getattr(exc, "code", "unavailable")
            self._logger.warning(
                "credential_retrieval_failed",
                path=ref.vault_path,
                error_code=error_code,
            )
            await write_audit_log(
                db,
                actor=user,
                action="CREDENTIAL_RETRIEVAL_FAILED",
                target_type="vault_ref",
                target_id=str(ref.id),
                request_id=grant.request_id,
                result="FAILURE",
                severity="WARNING",
                metadata={"protocol": protocol, "vault_path": ref.vault_path, "error_code": error_code},
            )
            raise

        self._logger.info("credential_retrieved", path=ref.vault_path, protocol=protocol)
        await write_audit_log(
            db,
            actor=user,
            action="CREDENTIAL_RETRIEVED",
            target_type="vault_ref",
            target_id=str(ref.id),
            request_id=grant.request_id,
            metadata={"protocol": protocol, "vault_path": ref.vault_path},
        )
        return material
