# SecurePAM

Risk-Adaptive Privileged Access Management platform. Controls privileged
access to Windows/Linux servers (RDP/SSH) and internal web applications,
through: authenticate → authorize → evaluate risk → approve if required →
grant JIT access → retrieve credentials → establish a monitored/recorded
session → revoke on expiry → audit everything.

**Current phase: 2 (foundation hardening).** Login, RBAC, the dashboard,
health checks, and the full data model exist and are tested. Asset/
Application/Policy management, the risk/approval/JIT engines, and the
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
  (plus 5 sample assets, 3 applications, 4 policies).

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

## Status

Implemented and tested: project scaffolding, Docker Compose, all 17
SQLAlchemy models with full FK referential integrity, Alembic migrations
(verified from an empty DB), DevAuth login/`/me`, RBAC foundation
(`RoleChecker`/`PermissionChecker` — not yet wired to any endpoint since
none exist to gate), dashboard (real DB-backed counts only), structured
logging + request IDs, consistent API error envelope, `/health`,
`/health/live`, `/health/ready`, pagination/sorting utilities, React
frontend shell (routing, auth context, protected routes, role-based nav).

Not implemented: Keycloak/OIDC, Vault/OpenBao, Guacamole (RDP), SSH
gateway, web reverse proxy, isolated browser, risk engine, policy engine,
approval workflow, JIT access, session recording, Wazuh/SIEM, Assets/
Applications/Policies/Users/Roles CRUD (UI currently shows an honest
"planned for Phase N" placeholder for each).
