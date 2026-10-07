# SecurePAM

Risk-Adaptive Privileged Access Management platform. Controls privileged
access to Windows/Linux servers (RDP/SSH) and internal web applications,
through: authenticate → authorize → evaluate risk → approve if required →
grant JIT access → retrieve credentials → establish a monitored/recorded
session → revoke on expiry → audit everything.

**Current phase: 3 (Assets, Applications, Policies & real RBAC).** Login,
RBAC, the dashboard, health checks, the full data model, and now Asset/
Application/Policy management (CRUD + enforcement + audit logging) exist
and are tested end-to-end. The risk/approval/JIT engines and the
RDP/SSH/web gateways are not built yet — see [Status](#status).

## Architecture

```
Control Plane                          Data Plane (not built yet)
──────────────                         ──────────────────────────
React (Vite/TS/Tailwind)               RDP Gateway (Guacamole)
   │  axios + TanStack Query           SSH Gateway
   ▼                                   Web Gateway (NGINX)
FastAPI (async)                        Isolated Browser
   │  SQLAlchemy 2.0 (async)
   ▼
PostgreSQL · Redis
```

The Control Plane decides *"can this user access this target?"* — auth,
RBAC, policy, risk, approval, JIT, audit. The Data Plane (future phases)
handles *"how does the session reach the target?"*. These are kept
deliberately separate; see `app/auth/base.py` for the specific boundary
between IdP identity and SecurePAM's own authorization.

**Identity vs. authorization:** Keycloak (future) or DevAuth (now)
answers *"who is this?"*. SecurePAM's own RBAC tables (`roles`,
`permissions`, `user_roles`) always answer *"what can they do?"* — a
token's own claimed roles are never trusted for that decision (see
`app/auth/base.py` and `tests/test_auth.py::test_token_claimed_roles_are_not_trusted`).

## Asset / Application / Policy management

**Assets** (`/api/v1/assets`) are registered infrastructure targets
(`WINDOWS_SERVER`, `WINDOWS_WORKSTATION`, `LINUX_SERVER`, `UNIX_SERVER`,
`NETWORK_DEVICE`, `OTHER`; protocols `RDP`/`SSH`/`HTTPS`/`HTTP`). No
credentials live on this model — that's a future OpenBao/Vault phase
(`app/models/vault_ref.py` already has the reference table).

**Applications** (`/api/v1/applications`) are registered internal web
apps. **There is no `/proxy?url=...` and there never will be** —
`target_url` isn't even a field clients can set; it's derived
server-side from `hostname`/`port`/`protocol` after SSRF validation
(`app/core/ssrf.py`). That validator blocks loopback, link-local
(which also covers every major cloud's `169.254.169.254` metadata
endpoint), the literal `localhost`, and malformed hosts — but
deliberately does NOT block private-network IPs or internal DNS names
like `admin.internal`, since registering exactly those targets is the
whole point of a PAM web gateway. True DNS-rebinding defense (resolve +
pin at connection time) is a future Web Gateway concern, not CRUD
validation — see the module docstring for the full reasoning.

**Policies** (`/api/v1/policies`) are pure data for the future Risk/
Policy Engine — no decision logic lives in the frontend or in this CRUD
layer. `allowed_roles`/`allowed_asset_types`/`allowed_environments`/
`allowed_protocols`/`allowed_days` are Postgres `ARRAY` columns where
empty/null means "no restriction on this dimension."

All three: soft-delete only (never hard-delete — `is_deleted`), PATCH
semantics for updates (partial body, `exclude_unset`), and deletion is
refused with `409` while any Session still actively references the
Asset/Application (`CREATED`/`STARTING`/`ACTIVE`/`TERMINATING`).

### RBAC permissions

Enforced via `PermissionChecker` (`app/core/deps.py`) on every endpoint
below — never via frontend route visibility. A denial (`403`) writes an
`ACCESS_DENIED` audit event before the exception propagates.

| Role | assets | applications | policies |
|---|---|---|---|
| ADMIN | full CRUD | full CRUD | full CRUD |
| OPERATOR | read | read | — |
| APPROVER | read | read | read |
| AUDITOR | read | read | read |

### API endpoints

```
GET    /api/v1/assets              ?page,page_size,sort_by,sort_order,environment,criticality,asset_type,enabled,search
POST   /api/v1/assets
GET    /api/v1/assets/{id}
PATCH  /api/v1/assets/{id}
DELETE /api/v1/assets/{id}          -> 204, soft delete; 409 if active sessions reference it

GET    /api/v1/applications         ?page,page_size,sort_by,sort_order,environment,criticality,access_mode,enabled,search
POST   /api/v1/applications
GET    /api/v1/applications/{id}
PATCH  /api/v1/applications/{id}
DELETE /api/v1/applications/{id}

GET    /api/v1/policies             ?page,page_size,sort_by,sort_order,enabled,risk_threshold
POST   /api/v1/policies
GET    /api/v1/policies/{id}
PATCH  /api/v1/policies/{id}
DELETE /api/v1/policies/{id}
```

Every list endpoint uses the shared `app/core/pagination.py` utilities
(`apply_sorting` validates `sort_by` against an explicit per-endpoint
allowlist — never an arbitrary client-controlled column — before
`paginate` applies LIMIT/OFFSET and returns `{items, total, page,
page_size, pages}`).

### Example: registering a production asset

```bash
curl -X POST http://localhost:8000/api/v1/assets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"LINUX-PROD-02","hostname":"prod02.internal","ip_address":"10.0.1.30",
       "port":22,"protocol":"SSH","asset_type":"LINUX_SERVER",
       "environment":"PRODUCTION","criticality":"HIGH","approval_required":true}'
```

### Security considerations

- **Mass assignment**: `id`/`created_at`/`updated_at`/`created_by`/
  `updated_by`/`is_deleted` are never fields on any Create/Update
  schema — they're always server-set.
- **404 vs disclosure**: a soft-deleted or nonexistent resource both
  return a plain `404` — a non-admin never learns a deleted resource
  ever existed.
- **IDOR**: not applicable in the traditional per-owner sense — these
  are organization-wide resources gated purely by role/permission, not
  by a `user_id` the client could swap.
- **Never trust the frontend** for role, user ID, permissions, target
  URL, or policy decisions — every one of those is re-derived or
  re-checked server-side on every request.

## Tech stack

- **Backend:** Python, FastAPI (async), SQLAlchemy 2.0 (async), Alembic, PostgreSQL, Redis, structlog
- **Frontend:** React, TypeScript, Vite, Tailwind, React Router, TanStack Query, axios
- **Future:** Keycloak (OIDC), OpenBao/Vault, Apache Guacamole, NGINX, Wazuh

## Local setup

### 1. Prerequisites

- Python 3.12+ (3.13 works; `asyncpg==0.32.0`/`bcrypt==4.0.1` are pinned
  specifically for 3.13 compatibility — see `requirements.txt` comments)
- Node 20+
- PostgreSQL 16 and Redis, reachable locally (via Homebrew, Docker, or
  `docker-compose.yml`'s `postgres`/`redis` services)

### 2. Database setup

```bash
createuser -s securepam                      # if the role doesn't exist
psql -d postgres -c "ALTER USER securepam WITH PASSWORD 'securepam_dev_password';"
createdb -O securepam securepam               # dev database
createdb -O securepam securepam_test          # test database (tests drop/recreate its tables every run)
```

### 3. Redis setup

```bash
redis-server /opt/homebrew/etc/redis.conf --daemonize yes   # Homebrew path shown; any local Redis works
redis-cli ping   # -> PONG
```

### 4. Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
# edit .env: point DATABASE_URL at localhost if not using docker-compose

alembic upgrade head        # apply migrations
uvicorn app.main:app --reload --port 8000
```

- API: http://localhost:8000
- Swagger: http://localhost:8000/docs (DEV_MODE only)
- `DEV_MODE=true` seeds four users on first boot: `admin/admin123`,
  `operator/operator123`, `approver/approver123`, `auditor/auditor123`
  (plus 5 sample assets, 3 applications, 4 policies — including a
  "Production Linux Access" policy matching the OPERATOR/SSH/PRODUCTION
  example from the Phase 3 spec).

### 5. Frontend

```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev -- --port 3000
```

- App: http://localhost:3000 — sign in with any seeded user above.

### 6. Docker Compose (alternative to steps 2–5)

```bash
cp .env.example .env
docker compose up --build        # postgres, redis, backend, frontend
docker compose --profile lab up --build   # + keycloak, guacamole, vault (not yet integrated)
```

## Migrations

```bash
cd backend && source .venv/bin/activate
alembic upgrade head                    # apply all pending migrations
alembic downgrade base                  # drop everything
alembic revision --autogenerate -m "describe change"   # after editing app/models/*.py
alembic check                           # fails if models and live schema disagree — run this after every model change
```

`migrations/env.py` keeps the `+asyncpg` driver in the URL deliberately —
stripping it (as an earlier version of this file did) silently falls back
to the sync `psycopg2` driver, which isn't even installed.

## Tests

See [`backend/tests/README.md`](backend/tests/README.md) for full details
(fixtures, what's covered, how to add a test). Quick start:

```bash
cd backend && source .venv/bin/activate
createdb -O securepam securepam_test   # once
export DATABASE_URL="postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam_test"
export REDIS_URL="redis://localhost:6379/0"
pytest -v
```

Frontend has no automated tests yet (no components complex enough to
warrant them past Phase 2) — verify with:

```bash
cd frontend
npm run typecheck      # tsc --noEmit
npm run build           # tsc && vite build
```

## Environment variables

See [`.env.example`](.env.example) for the full list with safe
placeholder values (no real secrets). Key ones for local dev:

| Variable | Purpose |
|---|---|
| `DEV_MODE` | `true` enables local JWT login + auto-seeding; `false` requires Keycloak (not implemented yet — see `app/auth/oidc_provider.py`) |
| `DATABASE_URL` | Must keep the `+asyncpg` driver suffix |
| `REDIS_URL` | Used by `/health/ready` and (later) JIT TTL enforcement |
| `SECRET_KEY` | Signs DevAuth JWTs — change in any non-local environment |
| `LOG_LEVEL`, `DEBUG` | `DEBUG=true` also raises the `sqlalchemy.engine` logger to INFO |
| `BACKEND_CORS_ORIGINS` | Must include whatever origin the frontend is actually served from |

Variables prefixed `POSTGRES_`, `REDIS_HOST`/`REDIS_PORT`, `NGINX_*`,
`GRAFANA_*` exist only for `docker-compose.yml`'s other services —
`Settings` (`app/core/config.py`) explicitly ignores unknown keys so
`.env` can be shared between the app and compose without either rejecting
the other's variables.

## Troubleshooting

**`asyncpg` fails to build from source** — you're likely on Python 3.13;
`asyncpg==0.29.0` doesn't have a wheel for it. This repo already pins
`0.32.0`; if you changed it back, re-pin.

**`password cannot be longer than 72 bytes` on login/seed** — `passlib`
1.7.4's bcrypt self-test breaks on `bcrypt>=4.1`. Already pinned to
`bcrypt==4.0.1` in `requirements.txt`; don't let a transitive install
upgrade it.

**Alembic fails with `No module named 'psycopg2'`** — something stripped
`+asyncpg` from the configured URL. Check `migrations/env.py` still uses
`settings.DATABASE_URL` unmodified.

**`sqlalchemy.exc.NoForeignKeysError` / `AmbiguousForeignKeysError` on
startup** — a relationship is missing an explicit `foreign_keys=` where a
table has more than one FK to the same target (see `User.roles` /
`UserRole.user` in `app/models/user.py` for the pattern, needed because
`UserRole.assigned_by` also points at `users.id`).

**Tests fail with "Event loop is closed" / "attached to a different
loop"** — you're running against a database engine using real connection
pooling. Tests must run with `ENVIRONMENT=test` so `app/database/session.py`
switches to `NullPool`; check your env vars, or that you didn't delete
that branch.

**`/health/ready` returns 503** — PostgreSQL or Redis isn't reachable at
the configured URL; it deliberately does NOT share `/health`'s always-200
behavior, so orchestrators can route around this instance.

**Frontend gets CORS errors in the browser console** — `BACKEND_CORS_ORIGINS`
in `.env` must include the *exact* origin the browser uses (`http://localhost:3000`,
not `http://127.0.0.1:3000` — they're different origins to a browser's CORS checks).

**A migration's `downgrade()` fails with a constraint-name error on
`op.drop_constraint(None, ...)`** — unlike `op.create_foreign_key(None, ...)`
(where `None` lets Alembic generate a name), `drop_constraint` needs the
*real* name. Find it with
`SELECT conname FROM pg_constraint WHERE conrelid = '<table>'::regclass AND contype = 'f'`
— Postgres's default is `<table>_<column>_fkey` unless a naming
convention is configured (none is, in this codebase).

**A Pydantic schema with an `Enum` field stores `"AssetType.WINDOWS_SERVER"`
instead of `"WINDOWS_SERVER"`** — set `model_config = ConfigDict(use_enum_values=True)`
on the schema (every schema in `app/schemas/{assets,applications,policies}.py`
already does this) so `.model_dump()` yields plain strings before they
reach the ORM constructor.

## Status

Implemented and tested: project scaffolding, Docker Compose, all 17
SQLAlchemy models with full FK referential integrity, Alembic migrations
(verified from an empty DB), DevAuth login/`/me`, dashboard (real
DB-backed counts only), structured logging + request IDs, consistent API
error envelope, `/health`, `/health/live`, `/health/ready`,
pagination/sorting utilities, React frontend shell (routing, auth
context, protected routes, role-based nav) — and, as of Phase 3, full
Asset/Application/Policy CRUD with real RBAC enforcement
(`PermissionChecker` now actually gates every endpoint above, writing an
audit event on both success and denial), SSRF-safe Application
registration, and real Assets/Applications/Policies pages in the
frontend (search, filter, sort, pagination, create/edit/delete — no
fake data anywhere).

Not implemented: Keycloak/OIDC, Vault/OpenBao, Guacamole (RDP), SSH
gateway, web reverse proxy, isolated browser, risk engine, approval
workflow, JIT access, session recording, Wazuh/SIEM, Users/Roles CRUD
(UI still shows an honest "planned for Phase N" placeholder for those
and for Access Requests/Sessions/Recordings/Audit Logs/Risk Center/Vault).
