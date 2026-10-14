"""
Shared pytest fixtures.

Tests run against a dedicated `securepam_test` PostgreSQL database (never
the dev database) and a real Redis instance — both must be reachable at
the URLs below (override via env vars if needed). Environment variables
are set BEFORE any `app.*` module is imported anywhere in the test session,
since `app.core.config.settings` is a module-level singleton read once at
import time.
"""

import os

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ["DEV_MODE"] = "true"
os.environ["ENVIRONMENT"] = "test"
# Ordinary tests never talk to a real OpenBao, even if backend/.env selects
# it — live tests (tests/test_openbao_live.py) are opt-in and build their
# own provider from OPENBAO_LIVE_* variables.
os.environ["SECRET_PROVIDER"] = "mock"
os.environ["RDP_GATEWAY_ENABLED"] = "false"  # tests inject fake gateways explicitly

from typing import AsyncGenerator, List  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app.core.security import create_dev_access_token, hash_password  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.session import async_session_factory, engine  # noqa: E402
from app.main import _seed_default_data, app  # noqa: E402
from app.models.role import Role  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _prepared_database():
    """
    Build a clean schema via SQLAlchemy metadata and seed it with the same
    default RBAC roles/permissions/users/sample data the real app seeds on
    first DEV_MODE boot (by calling the exact same function, not a copy of
    its logic).

    Function-scoped (re-run before EVERY test) rather than once per session:
    once Phase 3 added tests that create/update/delete rows, a session-scoped
    seed meant later tests' exact-count assertions (e.g. "total == 5 assets")
    broke depending on what earlier tests in the same run had already
    inserted. Each test now starts from an identical, pristine DB — the
    per-test drop/create/reseed cost is small and correctness matters more.

    This intentionally does NOT go through Alembic — that migration path
    (upgrade from a truly empty DB, drift-check, downgrade) is exercised
    for real in test_migrations.py against a disposable database. Re-running
    Alembic for every test would only slow things down without testing
    anything this fixture doesn't already cover for app behavior.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    await _seed_default_data(include_sample_targets=True)  # sample targets are test fixtures

    yield

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def issue_token(username: str, roles: List[str] | None = None) -> str:
    """
    Build a dev JWT the same way /auth/login does. `roles` only lands in
    the TOKEN's claims (TokenIdentity.token_roles) — it is never consulted
    for authorization, which always comes from the local DB. Tests exploit
    this on purpose to prove that claim is actually true (see
    test_auth.py::test_token_claimed_roles_are_not_trusted).
    """
    return create_dev_access_token(subject=username, roles=roles or [])


@pytest.fixture
def admin_token() -> str:
    return issue_token("admin", ["ADMIN"])


@pytest.fixture
def operator_token() -> str:
    return issue_token("operator", ["OPERATOR"])


@pytest.fixture
def approver_token() -> str:
    return issue_token("approver", ["APPROVER"])


@pytest.fixture
def auditor_token() -> str:
    return issue_token("auditor", ["AUDITOR"])


@pytest_asyncio.fixture
async def operator2_token() -> str:
    """
    A second OPERATOR account, for IDOR tests: the seeded `operator` and
    `approver`/`auditor` fixtures aren't useful for "can peer user A see
    user B's own-scoped resource" since approver/auditor hold view-all
    permissions. Created directly in the DB (no Users CRUD API exists yet).
    """
    async with async_session_factory() as db:
        result = await db.execute(select(Role).where(Role.name == "OPERATOR"))
        operator_role = result.scalar_one()

        user = User(
            username="operator2",
            email="operator2@securepam.local",
            full_name="Second Operator",
            hashed_password=hash_password("operator2pass"),
            mfa_enabled=False,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=operator_role.id))
        await db.commit()

    return issue_token("operator2", ["OPERATOR"])


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
