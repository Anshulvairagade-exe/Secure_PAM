"""
Migration state: confirm a brand-new, empty database can be built from
zero using ONLY Alembic migrations (not Base.metadata.create_all — that's
what conftest.py uses for app behavior tests, which is a different claim),
that the resulting schema exactly matches the SQLAlchemy models (no
autogenerate drift), and that downgrade/upgrade are both reversible.

Runs against its own disposable database (`securepam_migration_test`),
never the shared `securepam_test` database the rest of the suite uses, via
`alembic` as a subprocess so each invocation re-reads a fresh env/config.
"""

import os
import subprocess
import sys
from pathlib import Path

import asyncpg
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
MAINTENANCE_DSN = "postgresql://securepam:securepam_dev_password@localhost:5432/postgres"
MIGRATION_TEST_DB = "securepam_migration_test"
MIGRATION_TEST_URL = (
    f"postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/{MIGRATION_TEST_DB}"
)


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": MIGRATION_TEST_URL, "DEV_MODE": "true"}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def fresh_migration_database():
    async def _create():
        conn = await asyncpg.connect(MAINTENANCE_DSN)
        try:
            await conn.execute(f'DROP DATABASE IF EXISTS "{MIGRATION_TEST_DB}"')
            await conn.execute(f'CREATE DATABASE "{MIGRATION_TEST_DB}" OWNER securepam')
        finally:
            await conn.close()

    async def _drop():
        conn = await asyncpg.connect(MAINTENANCE_DSN)
        try:
            await conn.execute(f'DROP DATABASE IF EXISTS "{MIGRATION_TEST_DB}"')
        finally:
            await conn.close()

    import asyncio

    asyncio.run(_create())
    yield
    asyncio.run(_drop())


def test_upgrade_head_succeeds_from_empty_database(fresh_migration_database):
    result = _run_alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr


def test_schema_matches_models_with_no_drift(fresh_migration_database):
    """`alembic check` fails (non-zero exit) if the live schema and the
    SQLAlchemy model metadata disagree in any way — this is what caught
    the sessions.recording_id use_alter FK silently missing from the
    initial migration during Phase 2 hardening."""
    upgrade = _run_alembic("upgrade", "head")
    assert upgrade.returncode == 0, upgrade.stderr

    check = _run_alembic("check")
    assert check.returncode == 0, check.stdout + check.stderr
    assert "No new upgrade operations detected" in check.stdout + check.stderr


def test_downgrade_then_upgrade_is_reversible(fresh_migration_database):
    upgrade = _run_alembic("upgrade", "head")
    assert upgrade.returncode == 0, upgrade.stderr

    downgrade = _run_alembic("downgrade", "base")
    assert downgrade.returncode == 0, downgrade.stderr

    reupgrade = _run_alembic("upgrade", "head")
    assert reupgrade.returncode == 0, reupgrade.stderr
