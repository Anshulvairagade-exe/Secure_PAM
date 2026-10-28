# SecurePAM

**Risk-adaptive Privileged Access Management.** Nobody connects to a server or an internal web app directly: a user asks
for access, SecurePAM decides (policy + explainable risk score + human approval when needed), issues a time-boxed
**just-in-time grant**, and then opens the connection on the user's behalf — fetching the credential from a vault the user
never sees, relaying the session through a gateway, recording it, and cutting it off the moment the grant ends.
Every step is audited.

```
authenticate → authorize (RBAC) → request → policy + risk → approval (if required)
   → JIT grant → credential checkout (OpenBao) → gateway session (SSH / RDP / isolated browser)
   → recording + live monitoring → expiry / revoke / terminate → audit trail + Risk Centre
```

Two principles run through everything:

1. **Identity and authorization are separate.** Keycloak (or the dev login) only answers *who is this?*. What a user may
   do is always decided by SecurePAM's own RBAC tables — roles claimed inside a token are never trusted.
2. **Fail closed.** Missing recording, sealed vault, expired grant, unknown SSH host key, unexpected destination — each one
   stops the session rather than degrading silently.

---

## Features

| Area | What it does |
|---|---|
| **Identity** | Keycloak OIDC with password + TOTP MFA; a dev username/password login for development and tests |
| **RBAC** | `ADMIN`, `OPERATOR`, `APPROVER`, `AUDITOR` roles enforced per route; own-scope callers get `404` for other users' objects |
| **Access requests** | Policy evaluation (roles, asset types, environments, protocols, days, business hours) plus a deterministic, explainable risk score |
| **Approvals** | Risk can escalate scrutiny but never grant what policy denied; self-approval is blocked |
| **JIT grants** | Duration clamped to policy (default 30 min, hard max 480); re-validated continuously by every gateway; admin revoke ends live sessions |
| **Secrets** | Credentials live only in OpenBao (KV v2, TLS, Raft, Shamir seal); the DB stores references; separate reader/writer identities; secrets wiped after the handshake |
| **SSH gateway** | Browser terminal (xterm.js) over WebSocket → asyncssh, pinned host keys, recording and command transcripts |
| **RDP gateway** | Browser RDP via Apache Guacamole (`guacd`), recordings, clipboard / file-transfer default-deny |
| **Isolated browser** | Disposable hardened Chromium per session (Xvfb + noVNC) behind an IP-pinned egress proxy, for internal HTTP/HTTPS apps |
| **Evidence** | Recordings written `O_EXCL`/`0600`, SHA-256 verified on every playback, reconciliation of incomplete recordings |
| **Audit & risk** | Full audit trail, optional SIEM sink, Risk Centre for detections (e.g. repeated MFA failures, suspicious commands) |
| **Admin UI** | Users, roles, assets, applications, policies, credentials, live sessions (monitor / terminate), recordings, settings |

### Risk scoring

Deterministic, not ML — the same inputs always give the same score, and every factor carries a code, points and a reason.

| Factor | Points | Factor | Points |
|---|---|---|---|
| `PRODUCTION_ASSET` | +30 | `OUTSIDE_BUSINESS_HOURS` | +20 |
| `CRITICAL_ASSET` | +25 | `UNKNOWN_CONTEXT` | +20 |
| `HIGH_CRITICALITY` | +15 | `REPEATED_AUTH_FAILURE` | +20 |
| `SENSITIVE_APPLICATION` | +20 | `UNUSUAL_ACCESS_PATTERN` | +20 |
| `HIGH_PRIVILEGE_ROLE` | +20 | `LONG_DURATION` (> 60 min) | +10 |

Levels: **LOW** 0–29 · **MEDIUM** 30–59 · **HIGH** 60–79 · **CRITICAL** 80+. Weights are overridable via `RISK_*` settings.

---

## Architecture

```
                        Operator / Approver / Auditor / Admin (browser)
                                          │
                         Frontend — React · TypeScript · Vite · Tailwind
                                          │  REST /api/v1 + WebSocket
                                          ▼
                    Backend — FastAPI (async) · SQLAlchemy 2.0 · Alembic
          ┌──────────────┬───────────┬────────┴─────┬──────────────┬─────────────────────┐
     PostgreSQL        Redis       OpenBao       Keycloak        guacd             Browser isolation
     system of      rate limits,  credentials   OIDC + TOTP     (RDP proxy)        (Chromium + noVNC
     record         session        (KV v2)      MFA realm           │               + egress proxy)
                    tickets                                         ▼                     │
                                                            Windows target         internal web app
                                  Linux target  ◄──── SSH (asyncssh) from the backend
```

The **control plane** decides *can this user access this target?* (auth, RBAC, policy, risk, approval, JIT, audit).
The **data plane** decides *how does the session reach the target?* (SSH, RDP and isolated-browser gateways). They are
kept deliberately separate.

### Repository layout

```
backend/              FastAPI control plane and gateways
  app/api/v1/         thin HTTP/WebSocket routes
  app/services/       core logic: access decisions, JIT, credentials, SSH/RDP/web sessions, recording, risk detection
  app/auth/           token validators: dev (HS256) and OIDC (Keycloak, RS256/JWKS)
  app/policies/       policy evaluator
  app/risk/           deterministic risk engine
  app/secret_providers/  OpenBao reader/writer + mock provider
  app/core/           config, permissions, audit writer, SIEM sink, rate limiter, SSRF guard
  migrations/         Alembic migrations
  tests/              pytest suite (runs against real PostgreSQL)
frontend/             React app (terminal, RDP and web clients, session players, admin pages)
infrastructure/       browser-isolation daemon + Chromium policy, Guacamole, OpenBao config
keycloak-extension/   Java event listener (securepam-otp-audit) for MFA failure auditing
policy-engine/        standalone, versioned policy-decision package (not yet wired into the backend)
scripts/              start / status scripts for the local stack
docs/                 architecture, startup runbook, developer reference
docker-compose.yml    Postgres, Redis, backend, frontend, Keycloak, Guacamole, OpenBao, Prometheus, Grafana
```

---

## Tech stack

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy 2.0 (async), Alembic, asyncssh, structlog
- **Frontend:** React 18, TypeScript, Vite, Tailwind, TanStack Query, xterm.js, guacamole-common-js, noVNC, Recharts
- **Data:** PostgreSQL 16, Redis
- **Security services:** OpenBao, Keycloak 24, Apache Guacamole (`guacd`)
- **Observability:** Prometheus, Grafana

---

## Getting started

### Prerequisites

- Python 3.12+ and Node 20+
- PostgreSQL 16 and Redis (local install or the `docker-compose.yml` services)
- Docker (for Keycloak, Guacamole, OpenBao and the browser-isolation daemon)

### Quick start with Docker Compose

```bash
cp .env.example .env          # then edit values
docker compose up --build
```

### Manual setup

**Database**

```bash
createuser -s securepam
psql -d postgres -c "ALTER USER securepam WITH PASSWORD 'securepam_dev_password';"
createdb -O securepam securepam
createdb -O securepam securepam_test     # used by the test suite
```

**Backend**

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env                  # point DATABASE_URL / REDIS_URL at your services
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

API at http://localhost:8000, Swagger UI at http://localhost:8000/docs (dev mode only).

With `DEV_MODE=true` the first boot seeds demo users — `admin`, `operator`, `approver`, `auditor` — plus sample assets,
applications and policies. Their development passwords are listed in the
[developer reference](docs/DEVELOPER-REFERENCE.md#local-setup). **Never enable `DEV_MODE` outside development.**

**Frontend**

```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev -- --port 3000
```

### Full local stack

For the full stack (two backend/frontend pairs — dev login and Keycloak MFA — plus OpenBao, Keycloak, Guacamole and
browser isolation), use the scripts:

```bash
./scripts/start-securepam.sh --dry-run   # show what would be started
./scripts/start-securepam.sh             # start anything not running, then print status
./scripts/status-securepam.sh            # read-only health report
```

See the [startup runbook](docs/SECUREPAM-STARTUP-RUNBOOK.md) for details.

---

## Testing

```bash
# backend
cd backend && source .venv/bin/activate
pytest

# frontend
cd frontend
npm run typecheck
npm test
```

The backend suite runs against a real PostgreSQL test database (`securepam_test`); its tables are dropped and recreated
on every run.

---

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/SECUREPAM-ARCHITECTURE.md) | End-to-end flow, components, auth, access workflow, secrets, gateways, recording, data model, security controls, known gaps |
| [Startup runbook](docs/SECUREPAM-STARTUP-RUNBOOK.md) | Start/status scripts, health checks, launch commands |
| [Developer reference](docs/DEVELOPER-REFERENCE.md) | API endpoints, RBAC matrix, request lifecycle, OpenBao setup and KV path conventions, environment variables, troubleshooting |
| [Policy engine](policy-engine/README.md) | The standalone policy-decision package |

---

## Status and known gaps

SecurePAM is a working lab/staging system, **not production-hardened**. Not yet implemented: isolated-browser session
recording, RDP command transcripts and Windows event correlation, MFA re-verification at credential checkout, and wiring
the standalone `policy-engine` into the request path. Operational gaps include RDP host-certificate validation and a
single-node OpenBao. The full list is in [Architecture §14](docs/SECUREPAM-ARCHITECTURE.md#14-live-state-versus-pending-and-known-gaps).

## Security

Do not commit `.env` files, tokens, keys or certificates — they are git-ignored. If you find a vulnerability, please
report it privately to the maintainer rather than opening a public issue.

## License

Licensed under the [Apache License 2.0](LICENSE).
