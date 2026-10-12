"""Credential retrieval must follow JIT and must not record secret values."""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_request_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secrets.base import SecretDeniedError, SecretMaterial, SecretNotFoundError, SecretUnavailableError
from app.secrets.retrieval import CredentialRetrievalService
from app.services.jit_service import JITService

SECRET = "synthetic-secret-value"
PATH = "secret/targets/lab-sample"
jit = JITService()


class ListLogger:
    def __init__(self):
        self.records = []

    def info(self, event, **kwargs):
        self.records.append((event, kwargs))

    def warning(self, event, **kwargs):
        self.records.append((event, kwargs))


class FakeProvider:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    async def read(self, vault_path: str):
        self.calls.append(vault_path)
        if self.error:
            raise self.error
        return SecretMaterial(username="lab-operator", password=SECRET)


async def _get(db_session: AsyncSession, model, **filters):
    conditions = [getattr(model, key) == value for key, value in filters.items()]
    result = await db_session.execute(select(model).where(*conditions))
    return result.scalar_one()


async def _grant(db_session, user, asset, protocol="SSH"):
    req = AccessRequest(
        request_number=generate_request_number(),
        user_id=user.id,
        asset_id=asset.id,
        protocol=protocol,
        reason="credential retrieval test",
        requested_duration=30,
        status="ACTIVE",
        approval_required=False,
        jit_required=True,
        mfa_required=False,
        recording_required=False,
    )
    db_session.add(req)
    await db_session.flush()
    return await jit.grant(
        db_session,
        request_id=req.id,
        user_id=user.id,
        asset_id=asset.id,
        application_id=None,
        protocol=protocol,
        duration_minutes=30,
        created_by=None,
    )


async def _ref(db_session, asset):
    ref = VaultRef(
        asset_id=asset.id,
        vault_path=PATH,
        secret_type="PASSWORD",
        username="lab-operator",
        is_active=True,
    )
    db_session.add(ref)
    await db_session.flush()
    return ref


def _audit_text(rows) -> str:
    return json.dumps([row.details for row in rows])


async def test_retrieval_without_jit_does_not_call_provider(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await _ref(db_session, asset)
    provider = FakeProvider()
    logger = ListLogger()
    service = CredentialRetrievalService(provider=provider, logger=logger)

    try:
        await service.retrieve(db_session, user=operator, target_id=asset.id, protocol="SSH")
        assert False, "expected denial"
    except SecretDeniedError as exc:
        assert SECRET not in str(exc)

    assert provider.calls == []
    assert SECRET not in json.dumps(logger.records)
    audits = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_RETRIEVAL_DENIED"))).scalars().all()
    assert len(audits) == 1
    assert SECRET not in _audit_text(audits)
    assert "vault_path" not in (audits[0].details or {})


async def test_retrieval_with_jit_reads_the_reference_only(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await _grant(db_session, operator, asset)
    await _ref(db_session, asset)
    provider = FakeProvider()
    logger = ListLogger()
    service = CredentialRetrievalService(provider=provider, logger=logger)

    material = await service.retrieve(db_session, user=operator, target_id=asset.id, protocol="SSH")

    assert provider.calls == [PATH]
    assert material.password == SECRET
    assert SECRET not in json.dumps(logger.records)
    audits = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_RETRIEVED"))).scalars().all()
    assert audits[0].details["vault_path"] == PATH
    assert SECRET not in _audit_text(audits)


async def test_missing_reference_does_not_call_provider(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await _grant(db_session, operator, asset)
    provider = FakeProvider()
    service = CredentialRetrievalService(provider=provider, logger=ListLogger())

    try:
        await service.retrieve(db_session, user=operator, target_id=asset.id, protocol="SSH")
        assert False, "expected missing reference"
    except SecretNotFoundError:
        pass

    assert provider.calls == []


async def test_provider_failure_is_audited_without_the_secret(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await _grant(db_session, operator, asset)
    await _ref(db_session, asset)
    provider = FakeProvider(error=SecretUnavailableError("OpenBao is unavailable"))
    service = CredentialRetrievalService(provider=provider, logger=ListLogger())

    try:
        await service.retrieve(db_session, user=operator, target_id=asset.id, protocol="SSH")
        assert False, "expected provider failure"
    except SecretUnavailableError as exc:
        assert SECRET not in str(exc)

    audits = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_RETRIEVAL_FAILED"))).scalars().all()
    assert audits[0].details["error_code"] == "unavailable"
    assert SECRET not in _audit_text(audits)


async def test_wrong_protocol_is_denied_before_the_provider(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await _grant(db_session, operator, asset, protocol="SSH")
    await _ref(db_session, asset)
    provider = FakeProvider()
    service = CredentialRetrievalService(provider=provider, logger=ListLogger())

    try:
        await service.retrieve(db_session, user=operator, target_id=asset.id, protocol="RDP")
        assert False, "expected denial"
    except SecretDeniedError:
        pass

    assert provider.calls == []
