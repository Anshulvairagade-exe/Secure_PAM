# SecurePAM Backend Tests

## Prerequisites

- PostgreSQL reachable, with a dedicated **`securepam_test`** database
  (never reuse the dev `securepam` database — the suite drops/recreates
  all tables on every run):

  ```bash
  createdb -O securepam securepam_test
  ```

- Redis reachable at `REDIS_URL`.
- `backend/.venv` with `requirements.txt` installed.

## Running

```bash
cd backend
source .venv/bin/activate
export DATABASE_URL="postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam_test"
export REDIS_URL="redis://localhost:6379/0"
pytest                 # all tests
pytest -v              # verbose
pytest tests/test_auth.py -v        # one file
pytest -k "rbac"        # by keyword
```

`tests/conftest.py` forces `DEV_MODE=true` and `ENVIRONMENT=test` regardless
of your shell env — tests always exercise DevAuth, and `ENVIRONMENT=test`
switches the DB engine to `NullPool` (see `app/database/session.py`): under
pytest, pooled asyncpg connections can get bound to an event loop that a
later test's loop has already closed, so pooling is simply disabled for
tests rather than fought with.

## What's covered, and how

| File | Covers |
|---|---|
| `test_health.py` | App startup, `/health`, `/health/live` (no deps touched), `/health/ready` (DB+Redis), `/health/detailed` |
| `test_auth.py` | Login success/failure, validation errors, `/me`, unauthorized access, and the core trust boundary (a token's claimed roles are never used for authorization — only the local RBAC tables are) |
| `test_dashboard.py` | Auth-gating and real DB-backed counts (no hard-coded numbers) |
| `test_rbac.py` | `RoleChecker`/`PermissionChecker` exercised directly against real seeded users — see the **scope note** below |
| `test_migrations.py` | A truly empty database built via `alembic upgrade head` only (not `create_all`), schema/model drift check (`alembic check`), and downgrade→upgrade reversibility — against its own disposable `securepam_migration_test` database |
| `test_pagination.py` | `app/core/pagination.py` utilities (no endpoint uses them yet) |

**Scope note on `test_rbac.py`:** as of Phase 2, no HTTP endpoint actually
applies `RoleChecker`/`PermissionChecker` yet — the first real role-gated
routes (Assets, Policies, etc. CRUD) land in a later phase. These tests
call the dependency classes directly with real `User` rows, proving the
mechanism itself is correct ahead of any route using it. Once Phase 3+
endpoints exist, add endpoint-level tests (`client.get(..., headers=...)`
asserting 403) alongside these.

## Fixtures (`tests/conftest.py`)

- `client` — an `httpx.AsyncClient` wired directly to the FastAPI app via
  `ASGITransport` (no running server needed).
- `db_session` — a raw `AsyncSession` for tests that need direct DB access
  (e.g. `test_rbac.py`, `test_pagination.py`).
- `admin_token` / `operator_token` / `approver_token` / `auditor_token` —
  dev JWTs for each seeded role.
- `_prepared_database` (session-scoped, autouse) — builds the schema via
  `Base.metadata.create_all` and seeds it by calling the app's own
  `_seed_default_data()`, so tests always see exactly what a fresh
  `DEV_MODE` boot seeds (admin/operator/approver/auditor users, 5 sample
  assets, 3 applications, 4 policies).

## Adding a new test

- Hitting an HTTP endpoint → use the `client` fixture.
- Needing a specific role → use the matching `*_token` fixture with
  `tests.conftest.auth_header(token)`.
- Needing raw DB state → use `db_session`.
- A new list endpoint → pair it with `app/core/pagination.py`'s
  `apply_sorting`/`paginate` and add coverage the way `test_pagination.py`
  does, not a one-off hand-rolled LIMIT/OFFSET.
