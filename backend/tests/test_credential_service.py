"""
CredentialService — authorization before retrieval, fail-closed behavior,
auditing, and no secret leakage. Exercised directly (like test_jit_service.py)
because by design there is no HTTP endpoint that returns credentials.

Every denial case also asserts the provider was never called: authorization
must complete before anything is read from the secret store.
"""

import logging
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_request_number
from app.models.access_request import AccessRequest
from app.models.approval import Approval
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secret_providers import MockSecretProvider, OpenBaoSecretProvider
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)

PATH = "securepam/assets/linux-dev-01"
PASSWORD = "PW-CANARY-7f3a-not-real"
TOKEN = "s.TOKENCANARY0123456789"


async def _get(db: AsyncSession, model, **filters):
    result = await db.execute(select(model).where(*[getattr(model, k) == v for k, v in filters.items()]))
    return result.scalar_one()


async def _scenario(
    db: AsyncSession, *, username="operator", asset_name="LINUX-DEV-01", protocol="SSH",
    request_status="ACTIVE", grant_status="ACTIVE", expires_in_minutes=30,
    ref_provider="mock", ref_path=PATH, with_ref=True,
) -> CheckoutRequest:
    """A fully valid Phase 4 outcome (ACTIVE request + live JIT grant) plus
    a credential reference for the asset. Tests then break one thing."""
    user = await _get(db, User, username=username)
    asset = await _get(db, Asset, name=asset_name)
    req = AccessRequest(
        request_number=generate_request_number(), user_id=user.id, asset_id=asset.id,
        protocol=protocol, reason="credential service test", requested_duration=30,
        status=request_status, approval_required=False, jit_required=True,
        mfa_required=False, recording_required=False,
    )
    db.add(req)
    await db.flush()
    now = datetime.now(timezone.utc)
    grant = JITGrant(
        request_id=req.id, user_id=user.id, asset_id=asset.id, protocol=protocol,
        granted_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=expires_in_minutes),
        status=grant_status,
    )
    db.add(grant)
    if with_ref:
        db.add(VaultRef(asset_id=asset.id, provider=ref_provider, vault_path=ref_path,
                        secret_type="PASSWORD", username="ref-user", is_active=True))
    await db.commit()
    return CheckoutRequest(user_id=user.id, access_request_id=req.id, jit_grant_id=grant.id,
                           asset_id=asset.id, source_ip="10.9.9.9")


def _provider(**kw) -> MockSecretProvider:
    return MockSecretProvider({PATH: {"username": "svc-linux", "password": PASSWORD}}, **kw)


async def _audit(db: AsyncSession, prefix="CREDENTIAL_"):
    result = await db.execute(
        select(AuditLog).where(AuditLog.action.like(f"{prefix}%")).order_by(AuditLog.timestamp)
    )
    return result.scalars().all()


async def _expect_denied(db, req, reason, provider=None):
    provider = provider or _provider()
    with pytest.raises(CredentialAccessDenied) as exc:
        async with CredentialService(provider=provider).checkout(db, req):
            pytest.fail("checkout must not yield on denial")
    assert exc.value.reason == reason
    assert provider.reads == [], "secret store was read before authorization completed"

    rows = await _audit(db)
    assert [r.action for r in rows] == ["CREDENTIAL_RETRIEVAL_ATTEMPTED", "CREDENTIAL_RETRIEVAL_DENIED"]
    assert rows[1].result == "DENIED" and rows[1].details["reason"] == reason
    return rows


# --- success ---

async def test_authorized_checkout_yields_credential_then_wipes(db_session):
    req = await _scenario(db_session)
    provider = _provider()

    async with CredentialService(provider=provider).checkout(db_session, req) as cred:
        assert cred.username == "svc-linux"
        assert cred.reveal() == PASSWORD
        assert cred.version == 1
        held = cred
    assert held.is_wiped
    assert provider.reads == [PATH]

    rows = await _audit(db_session)
    assert [r.action for r in rows] == ["CREDENTIAL_RETRIEVAL_ATTEMPTED", "CREDENTIAL_RETRIEVED"]
    ok = rows[1]
    assert ok.result == "SUCCESS"
    assert ok.actor_id == req.user_id
    assert ok.target_type == "asset" and ok.target_id == str(req.asset_id)
    assert ok.request_id == req.access_request_id
    assert ok.source_ip == "10.9.9.9"
    assert ok.details["secret_reference"] == PATH
    assert ok.details["jit_grant_id"] == str(req.jit_grant_id)
    assert ok.details["provider"] == "mock"


async def test_username_falls_back_to_reference_metadata(db_session):
    req = await _scenario(db_session)
    provider = MockSecretProvider({PATH: {"password": PASSWORD}})
    async with CredentialService(provider=provider).checkout(db_session, req) as cred:
        assert cred.username == "ref-user"


async def test_wiped_even_if_caller_raises(db_session):
    req = await _scenario(db_session)
    with pytest.raises(ValueError):
        async with CredentialService(provider=_provider()).checkout(db_session, req) as cred:
            held = cred
            raise ValueError("gateway handshake failed")
    assert held.is_wiped


# --- user / RBAC / IDOR ---

async def test_unknown_user_denied(db_session):
    req = await _scenario(db_session)
    rows = await _expect_denied(db_session, replace(req, user_id=uuid.uuid4()), "USER_NOT_FOUND_OR_INACTIVE")
    assert rows[1].actor_id is None


async def test_inactive_user_denied(db_session):
    req = await _scenario(db_session)
    user = await db_session.get(User, req.user_id)
    user.is_active = False
    await db_session.commit()
    await _expect_denied(db_session, req, "USER_NOT_FOUND_OR_INACTIVE")


async def test_user_without_sessions_create_denied(db_session):
    req = await _scenario(db_session, username="auditor")
    await _expect_denied(db_session, req, "PERMISSION_DENIED")


async def test_peer_cannot_use_another_users_request_and_grant(db_session, operator2_token):
    """IDOR: operator2 presents operator's (valid) request + grant IDs."""
    req = await _scenario(db_session)
    peer = await _get(db_session, User, username="operator2")
    await _expect_denied(db_session, replace(req, user_id=peer.id), "ACCESS_REQUEST_USER_MISMATCH")


# --- access request ---

async def test_missing_request_denied(db_session):
    req = await _scenario(db_session)
    rows = await _expect_denied(db_session, replace(req, access_request_id=uuid.uuid4()), "ACCESS_REQUEST_NOT_FOUND")
    assert rows[1].request_id is None  # FK column left empty; claimed id kept in metadata
    assert rows[1].details["access_request_id"]


@pytest.mark.parametrize("status", ["APPROVAL_REQUIRED", "APPROVED", "REJECTED", "DENIED", "CANCELLED", "EXPIRED"])
async def test_request_not_active_denied(db_session, status):
    req = await _scenario(db_session, request_status=status)
    await _expect_denied(db_session, req, "ACCESS_REQUEST_NOT_ACTIVE")


async def test_request_for_other_target_denied(db_session):
    req = await _scenario(db_session)
    other = await _get(db_session, Asset, name="LINUX-STAGING-01")
    await _expect_denied(db_session, replace(req, asset_id=other.id), "ACCESS_REQUEST_TARGET_MISMATCH")


async def test_approval_required_without_approved_approval_denied(db_session):
    req = await _scenario(db_session)
    ar = await db_session.get(AccessRequest, req.access_request_id)
    ar.approval_required = True
    db_session.add(Approval(request_id=ar.id, status="PENDING"))
    await db_session.commit()
    await _expect_denied(db_session, req, "APPROVAL_MISSING")


async def test_approval_required_with_approved_approval_allowed(db_session):
    req = await _scenario(db_session)
    ar = await db_session.get(AccessRequest, req.access_request_id)
    ar.approval_required = True
    approver = await _get(db_session, User, username="approver")
    db_session.add(Approval(request_id=ar.id, status="APPROVED", approver_id=approver.id,
                            decided_at=datetime.now(timezone.utc)))
    await db_session.commit()
    async with CredentialService(provider=_provider()).checkout(db_session, req) as cred:
        assert cred.reveal() == PASSWORD


# --- target ---

@pytest.mark.parametrize(
    "change, reason",
    [
        ({"enabled": False}, "ASSET_DISABLED"),
        ({"status": "MAINTENANCE"}, "ASSET_DISABLED"),
        ({"status": "INACTIVE"}, "ASSET_DISABLED"),
        ({"is_deleted": True}, "ASSET_NOT_FOUND"),
    ],
)
async def test_unavailable_target_denied(db_session, change, reason):
    req = await _scenario(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    for k, v in change.items():
        setattr(asset, k, v)
    await db_session.commit()
    await _expect_denied(db_session, req, reason)


# --- JIT grant ---

async def test_missing_grant_denied(db_session):
    req = await _scenario(db_session)
    await _expect_denied(db_session, replace(req, jit_grant_id=uuid.uuid4()), "JIT_GRANT_NOT_FOUND")


@pytest.mark.parametrize("status", ["REVOKED", "EXPIRED"])
async def test_revoked_or_expired_grant_denied(db_session, status):
    req = await _scenario(db_session, grant_status=status)
    await _expect_denied(db_session, req, f"JIT_GRANT_{status}")


async def test_lapsed_active_grant_is_expired_and_denied(db_session):
    req = await _scenario(db_session, expires_in_minutes=-1)
    await _expect_denied(db_session, req, "JIT_GRANT_EXPIRED")

    grant = await db_session.get(JITGrant, req.jit_grant_id)
    await db_session.refresh(grant)
    assert grant.status == "EXPIRED"
    expired = await _audit(db_session, prefix="JIT_EXPIRED")
    assert len(expired) == 1


async def test_grant_from_another_request_denied(db_session):
    """Two valid request/grant pairs for the same user+asset: mixing them
    (request A with grant B) is a binding mismatch, not a pass."""
    a = await _scenario(db_session)
    b = await _scenario(db_session, with_ref=False)
    await _expect_denied(db_session, replace(a, jit_grant_id=b.jit_grant_id), "JIT_GRANT_MISMATCH")


async def test_grant_for_other_user_denied(db_session, operator2_token):
    req = await _scenario(db_session)
    peer = await _get(db_session, User, username="operator2")
    grant = await db_session.get(JITGrant, req.jit_grant_id)
    grant.user_id = peer.id
    await db_session.commit()
    await _expect_denied(db_session, req, "JIT_GRANT_MISMATCH")


async def test_protocol_mismatch_denied(db_session):
    req = await _scenario(db_session, protocol="RDP")  # LINUX-DEV-01 is SSH
    await _expect_denied(db_session, req, "PROTOCOL_MISMATCH")


async def test_revoking_grant_cuts_off_subsequent_checkouts(db_session):
    from app.services.jit_service import JITService

    req = await _scenario(db_session)
    async with CredentialService(provider=_provider()).checkout(db_session, req):
        pass
    await JITService().revoke(db_session, await db_session.get(JITGrant, req.jit_grant_id))
    await db_session.commit()
    with pytest.raises(CredentialAccessDenied, match="JIT_GRANT_REVOKED"):
        async with CredentialService(provider=_provider()).checkout(db_session, req):
            pass


# --- session binding ---

async def _session(db, req: CheckoutRequest, **overrides) -> uuid.UUID:
    s = Session(
        session_number=f"SES-{uuid.uuid4().hex[:6].upper()}", user_id=req.user_id, asset_id=req.asset_id,
        request_id=req.access_request_id, jit_grant_id=req.jit_grant_id, protocol="SSH", status="STARTING",
    )
    for k, v in overrides.items():
        setattr(s, k, v)
    db.add(s)
    await db.commit()
    return s.id


async def test_bound_session_allowed(db_session):
    req = await _scenario(db_session)
    req = replace(req, session_id=await _session(db_session, req))
    async with CredentialService(provider=_provider()).checkout(db_session, req):
        pass
    rows = await _audit(db_session)
    assert rows[-1].session_id == req.session_id


async def test_session_bound_to_other_grant_denied(db_session):
    req = await _scenario(db_session)
    req = replace(req, session_id=await _session(db_session, req, jit_grant_id=None))
    await _expect_denied(db_session, req, "SESSION_MISMATCH")


async def test_finished_session_denied(db_session):
    req = await _scenario(db_session)
    req = replace(req, session_id=await _session(db_session, req, status="COMPLETED"))
    await _expect_denied(db_session, req, "SESSION_NOT_LIVE")


async def test_unknown_session_denied(db_session):
    req = await _scenario(db_session)
    await _expect_denied(db_session, replace(req, session_id=uuid.uuid4()), "SESSION_NOT_FOUND")


# --- credential reference ---

async def test_no_reference_denied(db_session):
    req = await _scenario(db_session, with_ref=False)
    await _expect_denied(db_session, req, "NO_CREDENTIAL_REFERENCE")


async def test_inactive_reference_ignored(db_session):
    req = await _scenario(db_session)
    ref = await _get(db_session, VaultRef, asset_id=req.asset_id)
    ref.is_active = False
    await db_session.commit()
    await _expect_denied(db_session, req, "NO_CREDENTIAL_REFERENCE")


async def test_ambiguous_reference_denied(db_session):
    req = await _scenario(db_session)
    db_session.add(VaultRef(asset_id=req.asset_id, provider="mock", vault_path="securepam/assets/other",
                            secret_type="PASSWORD", is_active=True))
    await db_session.commit()
    await _expect_denied(db_session, req, "AMBIGUOUS_CREDENTIAL_REFERENCE")


async def test_reference_for_other_provider_never_falls_back(db_session):
    """A ref registered against OpenBao must not be served by the mock."""
    req = await _scenario(db_session, ref_provider="openbao")
    await _expect_denied(db_session, req, "PROVIDER_MISMATCH")


@pytest.mark.parametrize(
    "path", ["securepam/../sys/mounts", "other/assets/x", "secret/data/securepam/assets/x", "/securepam/x"]
)
async def test_tampered_reference_path_denied(db_session, path):
    req = await _scenario(db_session, ref_path=path)
    await _expect_denied(db_session, req, "INVALID_SECRET_REFERENCE")


# --- provider failures (authorized, but fail closed) ---

@pytest.mark.parametrize(
    "provider, code",
    [
        (lambda: _provider(available=False), "PROVIDER_UNAVAILABLE"),
        (lambda: _provider(denied_paths=[PATH]), "PROVIDER_ACCESS_DENIED"),
        (lambda: MockSecretProvider({}), "SECRET_NOT_FOUND"),
        (lambda: MockSecretProvider({PATH: {"username": "x"}}), "MALFORMED_SECRET"),
    ],
)
async def test_provider_failure_fails_closed_and_is_audited(db_session, provider, code):
    req = await _scenario(db_session)
    with pytest.raises(CredentialUnavailable) as exc:
        async with CredentialService(provider=provider()).checkout(db_session, req):
            pytest.fail("must not yield")
    assert exc.value.reason == code

    rows = await _audit(db_session)
    assert [r.action for r in rows] == ["CREDENTIAL_RETRIEVAL_ATTEMPTED", "CREDENTIAL_RETRIEVAL_FAILED"]
    assert rows[1].result == "FAILURE" and rows[1].details["reason"] == code


# --- end to end through the real OpenBao provider (mocked HTTP) ---

def _openbao(handler) -> OpenBaoSecretProvider:
    return OpenBaoSecretProvider(
        addr="http://bao.test:8200", token=SecretStr(TOKEN), mount_point="secret",
        path_prefix="securepam", connect_timeout=1, request_timeout=1,
        transport=httpx.MockTransport(handler),
    )


async def test_openbao_provider_end_to_end(db_session):
    req = await _scenario(db_session, ref_provider="openbao")
    body = {"data": {"data": {"username": "svc", "password": PASSWORD}, "metadata": {"version": 4}}}
    provider = _openbao(lambda r: httpx.Response(200, json=body))
    async with CredentialService(provider=provider).checkout(db_session, req) as cred:
        assert cred.reveal() == PASSWORD and cred.version == 4
    rows = await _audit(db_session)
    assert rows[-1].details["secret_version"] == 4


async def test_openbao_unavailable_fails_closed(db_session):
    req = await _scenario(db_session, ref_provider="openbao")

    def down(request):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(CredentialUnavailable, match="PROVIDER_UNAVAILABLE"):
        async with CredentialService(provider=_openbao(down)).checkout(db_session, req):
            pass


# --- leakage ---

async def test_no_secret_or_token_in_audit_logs_or_exceptions(db_session, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    req = await _scenario(db_session, ref_provider="openbao")
    body = {"data": {"data": {"username": "svc", "password": PASSWORD}, "metadata": {"version": 1}}}
    async with CredentialService(provider=_openbao(lambda r: httpx.Response(200, json=body))).checkout(db_session, req) as cred:
        assert PASSWORD not in repr(cred)

    denied_body = {"errors": [f"permission denied {TOKEN}"]}
    with pytest.raises(CredentialUnavailable) as exc:
        async with CredentialService(provider=_openbao(lambda r: httpx.Response(403, json=denied_body))).checkout(db_session, req):
            pass
    assert TOKEN not in str(exc.value) and exc.value.__cause__ is None

    result = await db_session.execute(select(AuditLog))
    for row in result.scalars().all():
        blob = repr((row.details, row.target_id, row.action))
        assert PASSWORD not in blob and TOKEN not in blob

    captured = capsys.readouterr()
    for text in (caplog.text, captured.out, captured.err):
        assert PASSWORD not in text and TOKEN not in text
