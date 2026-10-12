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

`tests/conftest.py` forces `DEV_MODE=true`, `ENVIRONMENT=test` and
`SECRET_PROVIDER=mock` regardless
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
| `test_risk_engine.py` | Every risk factor individually, score/level boundaries (LOW/MEDIUM/HIGH/CRITICAL), explainability (`score == sum(points)`) — `now` always injected via `RiskContext`, never wall-clock |
| `test_policy_engine.py` | Role/protocol/environment/asset-type restrictions, business-hours + allowed-days, duration clamping (not rejection), explicit `deny_access`, the no-policy/disabled-policy fail-safe default |
| `test_access_requests.py` | XOR target validation, protocol-mismatch/disabled-target/excessive-duration 422s, privilege-escalation resistance, IDOR (404 not 403 for a peer's request), own-vs-view-all list scoping, cancel state machine, and the deterministic decision-matrix outcomes (see note below) |
| `test_approvals.py` | Approve/reject, self-approval blocked (403), duplicate-decision blocked (409), mandatory rejection comment (422), RBAC on the approval queue, JIT duration clamped to the policy maximum on approval |
| `test_jit_service.py` | `JITService` exercised directly (no REST endpoint exists for it — see its module docstring): grant/validate/revoke/expire, wrong-user/wrong-target/wrong-protocol denial, lazy-expiry |
| `test_secret_settings.py` | `SECRET_PROVIDER`/`OPENBAO_*` defaults and fail-safe validation (missing token/addr, bad URL, traversal in mount/prefix, production refuses mock and plain http), and that no validation error or repr ever contains the token |
| `test_secret_providers.py` | Path rules, read-only provider interface, mock provider reads/failures, OpenBao KV v2 parsing via `httpx.MockTransport` (versions, 401/403/404/429/5xx, timeouts, non-JSON, deleted/destroyed), token only in the header, health never sends the token, `Credential` redaction/wipe |
| `test_credential_service.py` | Every authorization check before retrieval (user, RBAC, IDOR, request status/owner/target/approval, disabled/deleted asset, missing/revoked/expired/lapsed/mismatched JIT grant, protocol, session binding, missing/ambiguous/tampered/wrong-provider reference); provider never called on denial; provider outages fail closed; audit rows; no secret/token in audit, logs or exceptions |
| `test_credential_refs.py` | Admin credential-ref endpoints: server-derived path, client can't pick path/provider or send a secret (422), RBAC for every non-admin role, and a sweep proving no HTTP response contains a retrieved secret |
| `test_openbao_live.py` | **Opt-in** (`OPENBAO_LIVE_TEST=1`): real OpenBao with the restricted token — read allowed; write/patch/delete/destroy/metadata and admin endpoints 403. Refuses to run with a privileged token; probes never touch the real secret |
| `test_session_endpoints.py` | Audit/session/recording endpoints: 401 without a token, RBAC per role, IDOR (a peer's session is 404 for detail and terminate), termination rules (owner or `sessions:terminate`, 409 when not live), RDP launch only through a live JIT grant + `CredentialService` (fails closed and marks the session FAILED; response never carries a credential or path; client can't supply identity), recording streaming confined to `RECORDING_STORAGE_PATH` (absolute, `..` and symlink escapes → 404) and audited |
| `test_phase4_audit.py` | `ACCESS_REQUEST_CREATED`/`POLICY_EVALUATED`/`RISK_EVALUATED`/`APPROVAL_REQUESTED` or `ACCESS_ALLOWED`/`ACCESS_DENIED` on creation; `ACCESS_REQUEST_CANCELLED`; `APPROVAL_GRANTED`+`JIT_GRANTED`; `APPROVAL_REJECTED` |

**Why some Phase 4 outcomes are tested via direct service calls, not
HTTP:** `OUTSIDE_BUSINESS_HOURS` depends on real wall-clock time, which
the HTTP route never lets a caller override (correctly — that's not a
param a client should control). So `test_access_requests.py`'s
decision-matrix tests (`test_policy_denial_yields_denied_status`,
`test_critical_risk_with_no_policy_is_denied`, etc.) call
`AccessDecisionService.create_request(..., now=<fixed datetime>)`
directly — `now` is a test-only parameter, never passed by the API
route — while everything RBAC/validation/IDOR-shaped goes through the
real `client` fixture and tolerates the wobble by construction (e.g.
using a policy with `require_approval=True` to force a deterministic
outcome regardless of exactly how much risk accumulates).

**Scope note on `test_rbac.py`:** written in Phase 2, before any endpoint
used `RoleChecker`/`PermissionChecker`. Kept because testing the
mechanism directly (bypassing FastAPI's dependency injection) is still
useful on its own — but the real, spec-required coverage ("test actual
HTTP endpoints") is in `test_assets.py` / `test_applications.py` /
`test_policies.py`. `PermissionChecker.__call__` now takes `request` and
`db` (it writes an `ACCESS_DENIED` audit event on denial), so calling it
directly here means passing both explicitly — see the top of the file.

## Live OpenBao tests (opt-in)

Ordinary runs never contact OpenBao. To verify a real server and the
restricted token (never a root token — the module aborts if the token can
read `sys/mounts`):

```bash
OPENBAO_LIVE_TEST=1 OPENBAO_LIVE_ADDR=http://127.0.0.1:8200 \
OPENBAO_LIVE_TOKEN="$SECUREPAM_BAO_TOKEN" pytest tests/test_openbao_live.py -v
```

## Fixtures (`tests/conftest.py`)

- `client` — an `httpx.AsyncClient` wired directly to the FastAPI app via
  `ASGITransport` (no running server needed).
- `db_session` — a raw `AsyncSession` for tests that need direct DB access
  (e.g. `test_rbac.py`, `test_pagination.py`).
- `admin_token` / `operator_token` / `approver_token` / `auditor_token` —
  dev JWTs for each seeded role.
- `operator2_token` — a second OPERATOR account, created directly in the
  DB (no Users CRUD API exists yet). Exists specifically for IDOR tests,
  where the seeded `approver`/`auditor` accounts are useless (they hold
  view-all permissions, so they're never the "peer who shouldn't see
  this" side of an IDOR check).
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
