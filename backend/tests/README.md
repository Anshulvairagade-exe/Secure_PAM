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
| `test_assets.py` | Asset CRUD at the HTTP level, RBAC per role, 404/422 handling, pagination/filtering/sorting |
| `test_applications.py` | Application CRUD, SSRF validation (localhost/loopback/link-local/metadata/malformed all rejected; legitimate internal hostnames allowed), `target_url` not client-controllable |
| `test_policies.py` | Policy CRUD, RBAC per role, validation (risk threshold, duration, allowed_roles entries), duplicate-name 409 |
| `test_audit.py` | Successful actions AND denials both produce a persisted `AuditLog` row, and audit metadata never contains more than the explicit keys the code writes |
| `test_rbac.py` | `RoleChecker`/`PermissionChecker` exercised directly against real seeded users (bypassing HTTP) — see the **scope note** below |
| `test_migrations.py` | A truly empty database built via `alembic upgrade head` only (not `create_all`), schema/model drift check (`alembic check`), and downgrade→upgrade reversibility — against its own disposable `securepam_migration_test` database |
| `test_pagination.py` | `app/core/pagination.py` utilities directly (now also exercised indirectly through every list endpoint's own tests) |

**Scope note on `test_rbac.py`:** written in Phase 2, before any endpoint
used `RoleChecker`/`PermissionChecker`. Kept because testing the
mechanism directly (bypassing FastAPI's dependency injection) is still
useful on its own — but the real, spec-required coverage ("test actual
HTTP endpoints") is in `test_assets.py` / `test_applications.py` /
`test_policies.py`. `PermissionChecker.__call__` now takes `request` and
`db` (it writes an `ACCESS_DENIED` audit event on denial), so calling it
directly here means passing both explicitly — see the top of the file.

## Fixtures (`tests/conftest.py`)

- `client` — an `httpx.AsyncClient` wired directly to the FastAPI app via
  `ASGITransport` (no running server needed).
- `db_session` — a raw `AsyncSession` for tests that need direct DB access
  (e.g. `test_rbac.py`, `test_pagination.py`).
- `admin_token` / `operator_token` / `approver_token` / `auditor_token` —
  dev JWTs for each seeded role.
- `_prepared_database` (**function-scoped**, autouse) — builds the schema
  via `Base.metadata.create_all` and seeds it by calling the app's own
  `_seed_default_data()`, so every single test starts from exactly what a
  fresh `DEV_MODE` boot seeds (admin/operator/approver/auditor users, 5
  sample assets, 3 applications, 4 policies) — no test sees rows another
  test created. This was session-scoped in Phase 2, when every test was
  read-only; Phase 3 added tests that create/update/delete rows, and a
  shared DB meant exact-count assertions (`total == 5`) broke depending on
  what ran earlier in the same session. Function scope costs some runtime
  (~75s for the full suite) but is the correct tradeoff — don't change it
  back without re-auditing every count-based assertion in the suite.

## Adding a new test

- Hitting an HTTP endpoint → use the `client` fixture.
- Needing a specific role → use the matching `*_token` fixture with
  `tests.conftest.auth_header(token)`.
- Needing raw DB state → use `db_session`.
- A new list endpoint → pair it with `app/core/pagination.py`'s
  `apply_sorting`/`paginate` and add coverage the way `test_pagination.py`
  does, not a one-off hand-rolled LIMIT/OFFSET.
