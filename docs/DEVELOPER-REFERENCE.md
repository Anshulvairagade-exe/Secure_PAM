# SecurePAM — developer reference

> Detailed API, workflow and OpenBao setup notes written during the earlier build phases. Phase/status statements here are historical — for the current state see [SECUREPAM-ARCHITECTURE.md](SECUREPAM-ARCHITECTURE.md).

Risk-Adaptive Privileged Access Management platform. Controls privileged
access to Windows/Linux servers (RDP/SSH) and internal web applications,
through: authenticate → authorize → evaluate risk → approve if required →
grant JIT access → retrieve credentials → establish a monitored/recorded
session → revoke on expiry → audit everything.

**Current phase: 4 (the core PAM decision engine).** Login, RBAC, Assets/
Applications/Policies CRUD, and now the full Access Request → Policy
Evaluation → Explainable Risk → Approval → JIT workflow exist and are
tested end-to-end against real PostgreSQL. OpenBao/Vault, Keycloak,
Guacamole/SSH/web gateways, and the Risk/Policy engines' own UI (beyond
what the request detail page shows) are not built yet — see [Status](#status).

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

## Access Requests, Policy Evaluation, Risk, Approval & JIT

This is the core PAM decision engine. One service — `AccessDecisionService`
(`app/services/access_decision.py`) — owns the entire pipeline; nothing
here is duplicated across API routes.

```
POST /access-requests
        │
        ▼
  load + validate target ──── not found / disabled / protocol
        │                     mismatch / both-or-neither target  ──▶ 422
        ▼
  load target's Policy (or: none assigned → fail-safe default)
        │
        ▼
  PolicyEvaluator.evaluate_access()  ──────────┐
   (app/policies/evaluator.py)                 │  kept deliberately
        │                                      │  separate — see
  evaluate_risk()  ────────────────────────────┘  "Risk vs. Policy" below
   (app/risk/engine.py)
        │
        ▼
  decision matrix (AccessDecisionService._decide) ─▶ DENIED | APPROVAL_REQUIRED | APPROVED
        │                                                  │              │
        │                                           Approval row    JITGrant created
        │                                           created          immediately
        ▼                                                  │              │
  AccessRequest persisted,                                 ▼              ▼
  RiskEvent persisted,                          POST /approvals/{id}/approve|reject
  audit events written                                     │
                                                    approve ─▶ JITGrant created
```

### Access Request lifecycle

```
PENDING ──────────┬─→ APPROVAL_REQUIRED ─┬─→ APPROVED ─┬─→ ACTIVE ─→ EXPIRED
 (transient —      │                      ├─→ REJECTED │
  see below)       ├─→ APPROVED ──────────┘             └─→ EXPIRED
                   ├─→ DENIED
                   ├─→ CANCELLED
                   └─→ EXPIRED
```

`PENDING` is the formal starting state but is never actually persisted at
rest: `AccessDecisionService.create_request()` runs policy + risk
evaluation synchronously inside the same request, so by the time
`POST /access-requests` returns, the row already reads `APPROVAL_REQUIRED`,
`APPROVED` (immediately followed by `ACTIVE` once the JIT grant is
created), or `DENIED`. The state exists for a future async/queued
evaluation model and because `ALLOWED_TRANSITIONS` needs a defined
starting point. Every transition is checked against that explicit map —
`check_transition()` raises (mapped to `409`) on anything not listed,
closing off state-transition bypass (approving an already-rejected
request, cancelling an active one, etc).

### Policy Evaluation vs. Risk Evaluation — kept separate on purpose

`PolicyEvaluator` (`app/policies/evaluator.py`) answers *"does the rules-
based policy for this target permit this request, and what controls does
it demand?"* `evaluate_risk()` (`app/risk/engine.py`) answers *"how
risky does this specific request look?"* Neither function calls the
other. `AccessDecisionService` is the only place they're combined — this
means either can be tuned, re-weighted, or unit-tested in total isolation
without touching the other, and the frontend's "Policy Decision" and
"Risk Evaluation" panels on the request detail page are genuinely
independent explanations, not one narrative split across two boxes.

**No policy assigned, or the assigned policy is disabled:** fail-safe
default — `allowed=True` (the request can still proceed to the approval
queue) but `approval_required=True`, `mfa_required=True`,
`max_duration=30`. More scrutiny when nothing explicit governs a target,
never less — and necessary in practice, since most registered Assets/
Applications won't have a Policy assigned.

**Policy evaluation checks, in order:** `deny_access` (explicit, always
wins) → `allowed_roles` → `allowed_asset_types` → `allowed_environments`
→ `allowed_protocols` → `business_hours_only` → `allowed_days`. An
over-long `requested_duration` is **clamped** to `max_session_duration`,
never rejected — the spec's own example: requested 120 minutes, policy
maximum 30 minutes → the grant is 30 minutes, not an error.

**Standalone policy engine (`policy-engine/`, not yet wired in).** A
separate, versioned, risk-adaptive evaluator with its own tests lives in
[`policy-engine/`](policy-engine/README.md). The backend still uses
`app/policies/evaluator.py`; adopting the module means replacing that
evaluator inside `AccessDecisionService`, not running both. Its store uses
the `policy_engine_policies` table, so it does not touch the backend's
`policies` table.

### Risk scoring

`app/risk/engine.py` — deterministic, explainable, **not** machine
learning, **not** an external model. Same inputs always produce the same
score. Every factor carries a `code`, `points`, and a human-readable
`reason`; `score == sum(points)`.

| Factor | Points | Fires when |
|---|---|---|
| `PRODUCTION_ASSET` | +30 | Target's `environment == PRODUCTION` |
| `CRITICAL_ASSET` | +25 | Asset target, `criticality == CRITICAL` |
| `HIGH_CRITICALITY` | +15 | Asset target, `criticality == HIGH` (mutually exclusive with CRITICAL_ASSET) |
| `SENSITIVE_APPLICATION` | +20 | Application target, `criticality` HIGH or CRITICAL |
| `HIGH_PRIVILEGE_ROLE` | +20 | Requester holds an ADMIN role |
| `OUTSIDE_BUSINESS_HOURS` | +20 | Outside 09:00–17:00 UTC, Mon–Fri |
| `UNKNOWN_CONTEXT` | +20 | Request's source IP couldn't be determined |
| `REPEATED_AUTH_FAILURE` | +20 | `User.failed_login_count > 0` |
| `UNUSUAL_ACCESS_PATTERN` | +20 | Requester's first-ever access request (no prior request history) |
| `LONG_DURATION` | +10 | `requested_duration > 60` minutes |

**Levels:** 0–29 `LOW` · 30–59 `MEDIUM` · 60–79 `HIGH` · 80+ `CRITICAL`.

> **These weights are this project's own choices for Phase 4's
> demonstrable, explainable engine** — not an industry standard, not
> derived from any external framework or real incident data, and not
> validated against anything beyond "does the resulting score make
> intuitive sense for the scenario." Tune `RISK_WEIGHTS` in
> `app/risk/engine.py` for a real deployment; the constant names are
> written to be found and argued with, not buried in conditionals.

### Decision matrix — risk can escalate scrutiny, never grant what policy didn't

```
policy.allowed == False        → DENIED                         (always — policy is authoritative)
risk == CRITICAL, no policy    → DENIED                         (fail-safe: nothing vouches for this target)
risk == CRITICAL, has policy   → APPROVAL_REQUIRED               (elevated/human approval)
risk == HIGH                   → APPROVAL_REQUIRED               (always, regardless of policy.auto_approve)
risk == MEDIUM / LOW           → policy-dependent:
                                    policy.require_approval OR NOT policy.auto_approve → APPROVAL_REQUIRED
                                    otherwise                                          → APPROVED
```

There is deliberately no path that reads "high risk = automatically
allowed" — see `test_access_requests.py::test_high_risk_forces_approval_even_with_auto_approve_policy`.

### Approval workflow

A pending `Approval` row (`status=PENDING`) is created the moment a
request needs human review — not retroactively once decided — so it
shows up in `GET /approvals` immediately. `POST /approvals/{id}/approve`
or `/reject`:

- **Self-approval is blocked** (`403`) — `approver.id == access_request.user_id` is checked before anything else state-related.
- **Double-decision is blocked** (`409`) — an approval already `APPROVED`/`REJECTED` can't be redecided.
- **Rejection requires a comment** (`422` without one); approval's comment is optional.
- Approving transitions the request `APPROVAL_REQUIRED → APPROVED → ACTIVE` and creates the JIT grant in the same call — see `AccessDecisionService.approve()`.

### JIT lifecycle

`JITService` (`app/services/jit_service.py`) is the **single authoritative
source of truth** for "is this grant currently valid?" — not a UI
countdown, not a client-side timer. `grant()` is the only place an
expiry is ever computed, and it always clamps to the policy/decision
maximum (`min(requested, policy.max_session_duration)`) — a caller
cannot hand it an arbitrary duration and have it honored past that
ceiling. `validate(user_id, target_id, protocol)` is the exact interface
future gateway integrations (Guacamole/RDP, SSH, Web) must call before
establishing a session; it also lazily flips a found-but-lapsed `ACTIVE`
grant to `EXPIRED` so stale rows don't linger just because nothing
checked them. `revoke()` is immediate and explicit (an admin pulling
access mid-session); `expire()` is for a future background sweep.

**No JIT REST endpoint exists in Phase 4** — this is deliberately a
Python-level service for the control plane and future gateway code, not
an HTTP surface the spec asked for. It's exercised directly in
`tests/test_jit_service.py` and in the Phase 4 verification workflow
below via a short script, the same way Phase 2 exercised
`PermissionChecker` directly before any endpoint used it.

### API endpoints

```
POST   /api/v1/access-requests              -> runs the full decision pipeline synchronously
GET    /api/v1/access-requests               ?page,page_size,sort_by,sort_order,status
GET    /api/v1/access-requests/{id}
POST   /api/v1/access-requests/{id}/cancel

GET    /api/v1/approvals                     ?page,page_size,sort_by,sort_order,status
GET    /api/v1/approvals/{id}
POST   /api/v1/approvals/{id}/approve        {comment?: string}
POST   /api/v1/approvals/{id}/reject         {comment: string}   # mandatory
```

No separate `/access-requests/{id}/approve|reject` — the spec explicitly
warned against duplicating state-changing logic across endpoints, so the
Approval resource above is the one canonical path; `/access-requests`
only exposes create/read/cancel.

### Security assumptions

- **Business hours are fixed** at 09:00–17:00 UTC, Monday–Friday
  (`app/core/business_hours.py`) — a real deployment needs this
  per-organization (timezone, holidays, shifts). Explicitly out of scope
  for a deterministic Phase 4 engine.
- **`UNKNOWN_CONTEXT`** only fires when the source IP is literally
  unavailable — it is not a substitute for real device/location
  fingerprinting (no such signal exists yet in this codebase).
- **`UNUSUAL_ACCESS_PATTERN`** is a simple, explainable rule (first-ever
  request), not a learned behavioral baseline — by design, since the
  risk engine must stay deterministic and non-ML.
- **The approval queue expiry** (`APPROVAL_EXPIRY_HOURS = 24` in
  `access_decision.py`) is a project-specific constant, not enforced by
  a background sweep yet — a request past its `expires_at` while still
  `APPROVAL_REQUIRED` is not automatically flipped to `EXPIRED` today;
  that's future work alongside JIT's own `expire()` sweep.
- Every field a client might want to forge — `requester_id`, `risk_score`,
  `risk_level`, `policy_decision`, `approval_required`, `jit_required`,
  `expires_at`, `status` — simply isn't a field on `AccessRequestCreate`
  (see `app/schemas/access_requests.py`); there's no value to "ignore"
  because there's no field to accept it into.

## Credential management (OpenBao)

SecurePAM never stores credentials. PostgreSQL's `vault_refs` table holds
only a **reference** — provider name, a server-derived path, the asset it
belongs to, an optional pinned KV v2 version, the (non-secret) username
and timestamps. The secret itself lives in OpenBao and is read on demand,
in-process, only for an authorized session.

```
gateway (future RDP/SSH) ──▶ CredentialService.checkout()
                               1. user active + sessions:create
                               2. access request: owner, target, ACTIVE, approval
                               3. asset: exists, enabled, status ACTIVE
                               4. JIT grant: bound to request/user/asset/protocol, live
                               5. session (optional): bound to all of the above, live
                               6. exactly one active vault_ref, provider matches
                             ──▶ SecretProvider.read_secret()   (only after 1–6 pass)
                             ──▶ Credential (redacted repr, wiped on context exit)
```

| Component | Location |
|---|---|
| Settings + fail-safe validation | `backend/app/core/config.py` |
| `SecretProvider` interface, exceptions, `Credential` | `backend/app/secret_providers/base.py` |
| `OpenBaoSecretProvider` (KV v2 over async httpx) | `backend/app/secret_providers/openbao.py` |
| `MockSecretProvider` (fake values only) | `backend/app/secret_providers/mock.py` |
| Path rules (prefix, no traversal) | `backend/app/secret_providers/paths.py` |
| Authorization + audit before retrieval | `backend/app/services/credential_service.py` |
| Admin reference management (no secrets) | `backend/app/api/v1/credential_refs.py` |

There is deliberately **no HTTP endpoint that returns a credential**. A
future gateway calls the service directly:

```python
from app.services.credential_service import CheckoutRequest, CredentialService

async with CredentialService().checkout(db, CheckoutRequest(
    user_id=user.id, access_request_id=req.id, jit_grant_id=grant.id,
    asset_id=asset.id, session_id=session.id, source_ip=ip,
)) as cred:
    handshake(username=cred.username, password=cred.reveal())
# cred is wiped here; CredentialAccessDenied / CredentialUnavailable otherwise
```

### Provider selection

| `SECRET_PROVIDER` | Behavior |
|---|---|
| `mock` (default) | In-memory fake credentials. Refused at startup when `ENVIRONMENT=production`; health shows `degraded` outside `DEV_MODE`. |
| `openbao` | Requires `OPENBAO_ADDR` and `OPENBAO_TOKEN`. Missing or invalid values fail **at startup** (`SettingsError`) — the app never silently switches to mock. `ENVIRONMENT=production` also requires `https://`. |

A `vault_refs` row records which provider it was registered against;
retrieval refuses a row whose provider differs from the running one.

### Environment variables

Set these in **`backend/.env`** (git-ignored; Settings resolves it
relative to `backend/`, regardless of the working directory):

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_PROVIDER` | `mock` | `mock` or `openbao` |
| `OPENBAO_ADDR` | — | `http(s)://host:port`, no path/credentials |
| `OPENBAO_MOUNT_POINT` | `secret` | KV v2 mount |
| `OPENBAO_TOKEN` | — | The **restricted** app token (below). Held as a `SecretStr`; never logged, echoed in errors, or sent to the health endpoint |
| `OPENBAO_SECRET_PATH_PREFIX` | `securepam` | Every reference must sit under `<mount>/data/<prefix>/…` |
| `OPENBAO_CONNECT_TIMEOUT_SECONDS` / `OPENBAO_REQUEST_TIMEOUT_SECONDS` | `3` / `5` | Separate connect/request timeouts |
| `OPENBAO_CA_CERT` | empty | CA bundle path for TLS with a private CA |

The older `VAULT_*` variables are superseded and no longer read by the
backend (the optional compose `vault` lab container still uses `VAULT_TOKEN`).
Under docker-compose, `127.0.0.1` is the container itself — point
`OPENBAO_ADDR` at `http://host.docker.internal:8200` for a host-run OpenBao.

### KV v2 path conventions

- Stored reference (`vault_refs.vault_path`) is **relative to the mount**:
  `securepam/assets/<secret-name>` — e.g. `securepam/assets/test-linux-01`.
- CLI form: `bao kv get secret/securepam/assets/test-linux-01`.
- HTTP / policy form inserts `data/`: `secret/data/securepam/assets/test-linux-01`.
- Expected keys: `username` (optional, falls back to the ref's username)
  plus `password` (PASSWORD), `private_key` (SSH_KEY), `api_key`, or
  `certificate`.
- Paths are never accepted from clients. Admins register a reference with
  a single validated **name** and the server derives the path:

```bash
curl -X PUT http://localhost:8000/api/v1/assets/<asset-id>/credential-ref \
  -H "Authorization: Bearer $ADMIN_JWT" -H "Content-Type: application/json" \
  -d '{"secret_name": "test-linux-01", "username": "fakeuser", "secret_type": "PASSWORD"}'
```

`GET` (`vault:read`) and `DELETE` (deactivate, `vault:manage`) use the
same URL; all three are ADMIN-only with the seeded roles and audited
(`CREDENTIAL_REF_SET` / `CREDENTIAL_REF_DEACTIVATED`).

### Local OpenBao development setup

The lab Compose profile starts OpenBao and applies `securepam-read` for you:

```bash
docker compose --profile lab up openbao openbao-init
```

That writes the synthetic secret `secret/securepam/assets/test-linux-01` and a non-root token into the `openbao_runtime` volume. When the backend container sees that file, it sets `SECRET_PROVIDER=openbao` and `OPENBAO_TOKEN` from the file. Do not paste the dev root token into `OPENBAO_TOKEN`.

To do the same steps by hand:

```bash
bao server -dev                                    # terminal 1 — prints a ROOT token
export BAO_ADDR=http://127.0.0.1:8200              # terminal 2, using the root token
bao kv put secret/securepam/assets/test-linux-01 username=fakeuser password='fake-only'
```

Restricted policy — the smallest grant the app needs (read data only):

```bash
bao policy write securepam-read - <<'EOF'
path "secret/data/securepam/assets/*" {
  capabilities = ["read"]
}
EOF

# Application token: restricted policy only, no default policy, renewable, bounded.
bao token create -policy=securepam-read -no-default-policy \
  -ttl=24h -display-name=securepam-backend -field=token
```

Paste that token into `backend/.env` as `OPENBAO_TOKEN=` (with
`SECRET_PROVIDER=openbao`). Never use the root token as `OPENBAO_TOKEN`.

Verified with this policy (`tests/test_openbao_live.py`): read of the
asset path → 200; write/patch/delete/destroy/metadata changes → 403; reads
outside `securepam/assets/` → 403; `sys/mounts`, `sys/policies`, `sys/auth`,
`auth/token/create` → 403. `bao kv get` works even with
`-no-default-policy`: the CLI's preflight `sys/internal/ui/mounts/...`
lookup is allowed for any token holding a capability under the mount.

### OpenBao on AWS (production)

The lab server above is in-memory, plain HTTP, and auto-unsealed — never
production. The production deployment lives in
`infrastructure/openbao/aws/` and is fully separate from local development:

| Piece | File |
|---|---|
| Server config (Raft, private bind, TLS, KMS seal) | `infrastructure/openbao/aws/bao-config.hcl` |
| App policy: read-only, exact win11-lab + kali paths | `infrastructure/openbao/aws/policies/securepam-app.hcl` |
| Writer policy: update-only on the same two paths | `infrastructure/openbao/aws/policies/securepam-writer.hcl` |
| EC2 + SG + IAM + KMS + Secrets Manager + NLB + DNS | `infrastructure/openbao/aws/terraform/` |
| Idempotent provision/rotate/verify tooling | `backend/scripts/openbao_aws_provision.py`, `infrastructure/openbao/aws/provision/provision.sh` |
| Full operator runbook | `infrastructure/openbao/aws/README.md` |

Architecture (single private node, no public ingress, no SSH — admin over
SSM): SecurePAM backends → TLS → internal NLB :443 (TCP passthrough) →
EC2 :8200 (OpenBao, Let's Encrypt cert for the private DNS name, Raft on
encrypted EBS). Auto-unseal via the KMS `awskms` plugin using the instance
role (no static AWS credentials); file audit device shipped to
CloudWatch. backend config is one static change:

```bash
SECRET_PROVIDER=openbao
OPENBAO_ADDR=https://bao.<your-zone>   # https enforced when ENVIRONMENT=production
OPENBAO_TOKEN=<restricted app token from Secrets Manager>
OPENBAO_CA_CERT=                        # empty: public LE chain verifies with system CAs
```

Operator flow (details + IAM JSON + backup/recovery in `aws/README.md`):
`terraform apply` → `provision.sh` (detects init state, never
reinitialises; mints 24h app + 1h writer orphan tokens into 0600 files) →
`provision.sh --verify-only` (reuses the token verifier: exact policy,
capabilities, real reads, denied write probe) → `--push-secrets` →
restrict the bootstrap credential. Credentials for win11-lab/kali are
stored with `--set-credential` (hidden prompt, writer identity only);
tokens rotate with `--rotate app|writer` (new token verified before the
old is revoked — no restart). Asset references in SecurePAM are unchanged,
admin-only, allowlisted, and audited; every OpenBao failure (sealed,
unreachable, TLS error, denied, expired token) fails closed.

Status: the Terraform, config, policies, provisioner and verifier are
implemented and unit-tested with mocks, but **not yet run against real
AWS** — do not claim the deployment works until bootstrap + `--verify-only`
succeed in the target account (remaining prerequisites are listed in
`aws/README.md` §1).

### Troubleshooting a 403 from `bao kv get`

The error text tells you which layer refused:

| Error text | Meaning | Fix |
|---|---|---|
| `preflight capability check returned 403 … secret/securepam/...` | Token has **no** capability anywhere under the mount — usually the token is bound to a misspelled/nonexistent policy, or the policy is empty | `bao token lookup` (as the restricted token) → check `policies`; re-create token with the exact policy name |
| `Error reading secret/data/securepam/...: … permission denied` | Mount discovery passed; the data read was refused — policy path is wrong (e.g. missing `data/`, or `metadata/`/`list` only) | Policy must name `secret/data/securepam/assets/*` with `read` |
| `permission denied` with no `Error reading …` line | Token invalid or expired | Create a new token; check `ttl` |
| `URL: GET …/sys/internal/ui/mounts/…` + 403 and an empty token | `BAO_TOKEN` is empty/unset in that shell | `printenv BAO_TOKEN \| wc -c` (length only — don't print it) |
| `configured Vault token contains non-printable characters` | Captured full `bao token create` table instead of `-field=token` | Re-create with `-field=token` |

### Secret-handling rules

- No credential value in PostgreSQL, HTTP responses, health output,
  exceptions, audit metadata, or logs — tests sweep for planted canary
  values across all of these.
- Audit events: `CREDENTIAL_RETRIEVAL_ATTEMPTED`, then `CREDENTIAL_RETRIEVED`,
  `CREDENTIAL_RETRIEVAL_DENIED` (with a reason code such as
  `JIT_GRANT_EXPIRED`, `ACCESS_REQUEST_USER_MISMATCH`, `PROVIDER_MISMATCH`),
  or `CREDENTIAL_RETRIEVAL_FAILED` (`PROVIDER_UNAVAILABLE`,
  `PROVIDER_ACCESS_DENIED`, …). Metadata carries IDs, the reference path,
  provider and version only.
- Fail closed: any authorization failure, missing/ambiguous reference, or
  provider error raises — no partial data, no fallback provider.
- `Credential` has a redacted `repr`, refuses pickling, and is wiped when
  the `checkout()` block exits. Python can't zero an immutable `str` in
  place, so this limits lifetime by dropping references rather than
  scrubbing memory.
- The OpenBao client sends the token only as the `X-Vault-Token` header,
  does not follow redirects, ignores proxy/netrc environment, and raises
  exceptions without the HTTP cause chained in.
- `backend/.dockerignore` keeps `backend/.env` out of built images.

### Grant lifetime bounds session lifetime

When a JIT grant is revoked or expires (`JITService.revoke`/`expire`, or the
lazy flip inside `validate`), every live session bound to it is marked
`EXPIRED`, its in-progress recording is finalized, and a
`SESSION_ENDED_BY_GRANT` event is recorded. Expiry is still evaluated
lazily (when something reads the grant) — a background sweep is future work,
and the real gateway must tear down the connection when a session leaves a
live state.

### Remaining production-hardening requirements

Update: the AWS deployment in `infrastructure/openbao/aws/` now implements
the Raft/TLS/seal, audit-device, and rotation items below (single-node;
untested against real AWS so far — see
[OpenBao on AWS](#openbao-on-aws-production)). Still open: machine auth
(AppRole/JWT instead of static rotated tokens), token-renewal loop, MFA at
checkout, dynamic secrets, connection pooling.

The local `bao server -dev` instance is **not** production: it is
in-memory, auto-unsealed, plain HTTP, and its root token is printed to the
terminal. Before production:

- Run OpenBao with persistent storage (integrated Raft), TLS everywhere
  (`https://` is enforced when `ENVIRONMENT=production`), and real
  seal/unseal (Shamir or auto-unseal via KMS/HSM); revoke the initial root token.
- Replace the static `OPENBAO_TOKEN` with a machine auth method
  (AppRole with response-wrapped secret IDs, Kubernetes, or JWT/OIDC) and
  short-lived, auto-renewed tokens; this needs a token-renewal loop that
  the current provider does not implement.
- Enable an OpenBao audit device and ship it to the SIEM alongside
  SecurePAM's own audit log.
- Rotation: `last_rotated` / `rotation_interval_days` exist on
  `vault_refs` but nothing rotates yet; consider dynamic secrets
  (e.g. SSH CA / database engines) instead of static passwords.
- MFA-at-checkout: `access_requests.mfa_required` is recorded but not
  re-verified at retrieval time, because DevAuth carries no MFA claim;
  enforce it once Keycloak/OIDC lands.
- Connection pooling: the provider opens a client per read, which is
  fine at current volume but should become a shared, lifespan-managed client.
- The gateways that call `checkout()` (RDP via Guacamole, SSH) still need
  to be built, and must create a bound `sessions` row first.

## Tech stack

- **Backend:** Python, FastAPI (async), SQLAlchemy 2.0 (async), Alembic, PostgreSQL, Redis, structlog
- **Frontend:** React, TypeScript, Vite, Tailwind, React Router, TanStack Query, axios
- **Secrets:** OpenBao (KV v2) via `SECRET_PROVIDER=openbao`; mock provider for dev/tests
- **Future:** Keycloak (OIDC), Apache Guacamole, NGINX, Wazuh

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
| `DEV_MODE` | `true` enables local JWT login, the DevAuth validator and seeded known-password accounts; startup refuses it unless `ENVIRONMENT` is `development` or `test`. `false` uses Keycloak OIDC (`app/auth/oidc_provider.py`) |
| `DATABASE_URL` | Must keep the `+asyncpg` driver suffix |
| `REDIS_URL` | Used by `/health/ready` and (later) JIT TTL enforcement |
| `SECRET_KEY` | Signs DevAuth JWTs. Startup refuses the placeholder (or anything under 32 characters) when `ENVIRONMENT=production` |
| `LOG_LEVEL`, `DEBUG` | `DEBUG=true` also raises the `sqlalchemy.engine` logger to INFO |
| `BACKEND_CORS_ORIGINS` | Must include whatever origin the frontend is actually served from |
| `SECRET_PROVIDER`, `OPENBAO_*` | Credential provider — see [Credential management (OpenBao)](#credential-management-openbao) |

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

## Local lab operations (verified 2026-10-15)

Local-only. Nothing here touches AWS, restarts OpenBao, or deletes data.
The AWS deployment in `infrastructure/openbao/aws/` is separate and
undeployed; behavior below was verified against the running lab, not
claimed from unit tests.

### Services and URLs

| Service | URL | Notes |
|---|---|---|
| Frontend (vite dev) | http://127.0.0.1:3000 | Serves `frontend/src` live; no rebuild needed |
| Backend API + Swagger | http://127.0.0.1:8000, `/docs` | Restart to load code changes (see below) |
| Keycloak | http://localhost:8080 (`/admin` = master console — use `localhost`, not `127.0.0.1`: the server's hostname is `localhost`, and the admin console hangs on "Loading the Admin UI" from the other origin) | Container `securepam-keycloak`; realm `securepam` |
| OpenBao dev | http://127.0.0.1:18200 (sealed=false, in-memory) | **Never restart/reinit**: secrets live only in memory |
| guacd / Guacamole | 127.0.0.1:4822 / 127.0.0.1:8081 | RDP gateway + recordings |
| Browser isolation daemon | http://127.0.0.1:6090 (loopback mgmt API) | Per-session VNC on 127.0.0.1:5910+ |

PostgreSQL and Redis run on the Mac host (Homebrew). Docker holds only
Keycloak (+postgres), Guacamole stack, and browser-isolation.

### Safe start/stop

```bash
# Validate compose before touching anything (starts nothing):
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml --profile lab config > /dev/null
# Backend (from repo root; env names only — values from files/process, never logged):
SECRET_PROVIDER=openbao OPENBAO_ADDR=http://127.0.0.1:18200 \
  OPENBAO_TOKEN="$(cat ~/.securepam/openbao-app-token)" \
  SECUREPAM_KNOWN_HOSTS_PATH=<scratchpad>/ssh/known_hosts \
  RECORDING_STORAGE_PATH=<scratchpad>/recordings-live RDP_RECORDING_PATH=<scratchpad>/recordings-live/rdp \
  RDP_GATEWAY_ENABLED=true GUACD_HOST=127.0.0.1 GUACD_PORT=4822 REDIS_URL=redis://127.0.0.1:6379/0 \
  BROWSER_ISOLATION_ENABLED=true BROWSER_ISOLATION_TOKEN_FILE=$PWD/infrastructure/browser-isolation/.isolation_token \
  KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8080 \
  KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=$HOME/.securepam/keycloak-audit-reader.secret \
  KEYCLOAK_MFA_SYNC_ENABLED=true \
  nohup backend/.venv/bin/python backend/.venv/bin/uvicorn app.main:app \
  --host 127.0.0.1 --port 8000 --app-dir backend >> ~/.securepam/backend.log 2>&1 &
# Frontend needs no restart (vite serves disk state); backend MUST be restarted after code changes.
# Migrations: `cd backend && ../backend/.venv/bin/python -m alembic current` must print the head
# (currently d4e5f6a7b8c9 risk_findings); `upgrade head` only if behind. Never downgrade/reset dev data.
# NEVER: docker compose down -v, bao operator init, OpenBao restart, realm/secret deletion.
```

### Keycloak MFA (local realm `securepam`)

- The realm's browser flow is bound to **SecurePAM Browser MFA** (username/password REQUIRED, OTP REQUIRED). Users without an enrolled authenticator are forced through `CONFIGURE_TOTP` (a realm default action) — no bypass. Service-account/client-credentials flows use the separate `clients` flow and are unaffected (verified: token grant works).
- The `securepam-audit-reader` service account holds **only** `realm-management/view-events` (verified live: `events` 200, `users`/`clients` 403). Its secret lives 0600 at `~/.securepam/keycloak-audit-reader.secret` and is wired via `KEYCLOAK_AUDIT_CLIENT_SECRET_FILE`.
- To enroll a test account: Keycloak admin console at http://localhost:8080/admin (NOT 127.0.0.1 — wrong origin hangs the console) → master login → `securepam` realm → Users → Add user (username, email, temporary password OFF not needed) → Credentials → set password (temporary OFF) → sign in once at the SecurePAM frontend via Keycloak → scan the QR with Google/Microsoft Authenticator → enter the 6-digit code. Valid code succeeds; wrong code/password is rejected as `invalid_grant` (not misclassified — Keycloak distinguishes `invalid_user_credentials` from OTP errors).
- OTP failures surface as Keycloak `LOGIN_ERROR` events → backend MFA sync (60s loop, `keycloak_mfa_sync_started/completed` in `backend.log`) → `MFA_FAILURE` audit rows → Risk Centre `MFA_FAILURES` rule. Re-syncs are idempotent (verified by test, no duplicates).
- Admin console access needs the Keycloak `kcadmin` password (set at container creation; not stored in this repo — ask the environment owner; never commit it).

### Local OpenBao reader/writer

- Reader (`~/.securepam/openbao-app-token`, `securepam-read` policy): verified with `backend/scripts/verify_openbao_token.py` — read-only on exactly `securepam/assets/kali` and `securepam/assets/win11-lab` (both return `username`+`password` fields), deny everywhere else, writes denied. Backend `/health/detailed` shows the token fingerprint (never the token).
- Writer: **configured locally** via `OPENBAO_WRITER_TOKEN_FILE` (`~/.securepam/openbao-writer-token`, 0600, outside the repo) on the `securepam-writer` policy (create+update on the registered paths only — verified: read/delete/sys/token-mint all denied; `GET /credential-provisioning/status` reports `configured:true`). Limitations: the token is local-only with ~24h TTL (re-mint + backend restart when it expires; rotation procedure in `infrastructure/openbao/aws/README.md`); it is a separate identity from the reader (startup refuses equality); teammates must mint their own local writer token — this setup does not transfer. AWS deployment has not occurred. Provisioning/rotation endpoints fail closed (`503 PROVISIONING_NOT_CONFIGURED`, `written_version:null`, existing references untouched — verified live).
- Asset credentials: `credential-ref/check` reports `ok` for Kali; check responses never contain secrets. Local OpenBao UI: none configured (`openbao_ui_url:null`); do not publish port 8200.

### Health, features, and fallbacks

- Health: `/health` (liveness), `/health/detailed` (authed; per-service incl. OpenBao fingerprint, gateways, recording storage).
- Admin Users (`/users`, ADMIN): create/edit/deactivate verified live; responses never contain hashes; self-deactivation refused; last-admin protection is unit-tested.
- Settings (`/settings`, `PUT /settings/session-policy`): values persist and revert (verified 2→3→2).
- Risk Centre (`/risk`, `/risk/summary`): findings come from real audit rows via deterministic rules; API totals match `risk_findings` exactly (currently 9 OPEN / 5 RESOLVED).
- Recordings: server-side completion + SHA-256 verified before streaming; replay is auditor/admin-only (operator gets 403 — verified). Isolated-browser sessions carry no recording artifact by design (launch is refused when recording is required); use session/audit logs as the fallback there.
- Theme: light/dark/system toggle, persisted in `localStorage`, applied pre-paint (`public/theme-init.js`, no flash) — verified across reload.

### Recovery

- Backend won't start: read the tail of `~/.securepam/backend.log`; missing `OPENBAO_TOKEN`/`OPENBAO_ADDR` fails fast with `SettingsError` (never silent mock fallback).
- Keycloak realm misconfigured: the change surface is one DB row (`realm.browser_flow`); master realm always stays usable for recovery. Never import old realm exports (they carry signing keys, hashes, TOTP seeds).
- OpenBao sealed/unreachable: backends fail closed; do NOT reinit (destroys in-memory secrets) — restart only the `bao server -dev` process if it died, then re-run provisioning per `infrastructure/openbao/init-lab.sh` semantics.

## Status

Implemented and tested: project scaffolding, Docker Compose, all 17
SQLAlchemy models with full FK referential integrity, Alembic migrations
(verified from an empty DB and from a populated one, both directions),
DevAuth login/`/me`, dashboard (real DB-backed counts only), structured
logging + request IDs, consistent API error envelope, `/health`,
`/health/live`, `/health/ready`, pagination/sorting utilities, full
Asset/Application/Policy CRUD with real RBAC enforcement and SSRF-safe
Application registration — and, as of Phase 4, the complete core
decision engine: Access Requests, the separated Policy/Risk evaluators,
the decision matrix, the Approval workflow (self-approval and
double-decision blocked, mandatory rejection reason), and `JITService`
as the authoritative grant/validate/revoke/expire service for future
gateways to call. React frontend: routing, auth context, protected
routes, role-based nav, Assets/Applications/Policies pages, and now
Access Requests (list/create/detail/cancel) and an Approvals queue —
all real API data, no fake numbers anywhere.

Phase 5 adds OpenBao KV v2 credential references and `CredentialService`
(authorized, audited, backend-only retrieval for future gateways) — see
[Credential management (OpenBao)](#credential-management-openbao).

### Sessions, recording and gateways (current)

- **SSH is the one deployed gateway.** The browser terminal (xterm.js over
  `/sessions/ssh/{id}/ws`) is bridged by an in-process AsyncSSH gateway:
  one-time ticket (first WebSocket frame, never the URL), host-key pinning
  (`SECUREPAM_KNOWN_HOSTS_PATH`), server-side credential injection from
  OpenBao, and a monitor that re-reads the session, grant, request, user
  and asset every second and closes the real connection on termination,
  expiry, revocation or deactivation.
- **Recording** is a server-side asciicast v2 file (terminal output and
  resizes; keystrokes are not captured) under `RECORDING_STORAGE_PATH`
  (mode 0600, never served statically). A recording is `COMPLETED` only
  when the recorder ran and its file was closed and SHA-256 hashed; if
  required recording cannot start or fails mid-session, the session is
  refused or ended. `POST /sessions/{id}/terminate` never marks a
  recording complete — the gateway that owns the recorder finalizes it,
  and a recording that never started is marked `FAILED`.
- **RDP goes through Apache Guacamole's guacd** (`infrastructure/guacamole/compose.yml`, Guacamole 1.6.0).
  SecurePAM's backend speaks the Guacamole protocol to guacd directly — exactly what Guacamole's own web
  app does for a browser — so no Guacamole admin API, token or database password is involved in a session
  and the Windows credential is never stored in Guacamole. Launch validates request/grant/asset/limit and
  checks the credential out; the browser then redeems a one-time ticket on
  `/sessions/rdp/{id}/ws` (first frame, never the URL). The backend re-validates, hands guacd the target
  (always the registered asset) and credential, relays the display/keyboard/mouse stream with an opcode
  allowlist, and marks the session ACTIVE only after guacd's first real display update. The per-second
  monitor (grant, request, user, asset, termination) closes guacd's connection, which ends the RDP
  connection. Termination, admin terminate-all, grant revocation and the two-session limit are the same
  code paths as SSH.
- **RDP recording** is guacd's own recording (`recording-path` per session, keystrokes excluded) on a bind
  mount the backend reads. Required recording must exist before any desktop frame is forwarded. After the
  connection closes the artifact is inspected: it is COMPLETED only if it exists inside the RDP recording
  root, is a well-formed Guacamole stream **with display frames**, and has been SHA-256 hashed; otherwise
  FAILED with the reason audited. Playback verifies the hash on every request. A screen recording does not
  prove which commands ran; Windows command attribution needs event telemetry (4688, PowerShell 4104,
  Sysmon), which is not integrated.
- **RDP configuration:** `RDP_GATEWAY_ENABLED=true`, `GUACD_HOST=127.0.0.1`, `GUACD_PORT=4822`,
  `RDP_RECORDING_PATH` (= the directory bind-mounted at `/recordings` into guacd; defaults to
  `<RECORDING_STORAGE_PATH>/rdp`). Security: `RDP_SECURITY=nla`; `RDP_IGNORE_CERT=true` because Windows
  lab servers use self-signed certificates (NLA/CredSSP still authenticates the exchange, but the
  certificate chain is not validated — set false and install a trusted certificate for production).
  guacd has no authentication of its own: it is published on `127.0.0.1` only, and anything able to reach
  it could drive RDP connections, so never expose that port.
- **Starting Guacamole:** `cd infrastructure/guacamole && docker compose up -d` (`.env` holds
  `GUAC_RECORDINGS_DIR`; the secret files `.db_password`, `.owner_password`, `.admin_password` are
  git-ignored). The image has no `*_FILE` support, so the entrypoint reads the DB password from the secret
  file; the schema/roles/admin password are applied only on a fresh database, and the stock
  `guacadmin/guacadmin` credential is replaced before the database accepts connections. Web UI:
  `http://127.0.0.1:8081/guacamole/` (loopback only; admin password in `.admin_password`).
- **Remote-desktop architecture decision (Guacamole/guacd kept; noVNC rejected).** Evidence from the live
  lab: the guacd path already delivers a real NLA-authenticated RDP connection, real Windows frames, key and
  mouse events, recordings that replay in the browser, admin termination and grant revocation. The only
  blocker observed was Windows' single-session rule ("Another user is signed in"), which a VNC server would
  not solve: a Windows VNC server attaches to the *console* session, so it shows whoever is signed in there,
  bypasses per-user Windows authentication, needs third-party software installed on every endpoint, and adds
  a network service to firewall and authenticate, plus a second recording format. Guacamole's own web client
  was also not adopted: it would put a Guacamole token and UI in the browser, whereas SecurePAM keeps the
  browser on its own one-time-ticket WebSocket and holds the credential server-side.
- **ACTIVE is not "desktop reached".** A session becomes ACTIVE when guacd delivers real display frames,
  which can be the Windows sign-in, lock or "another user is signed in" screen. guacd does not report
  Windows logon completion, so desktop reachability is verified visually, never inferred from frames.
- **Recording playback** replays the hash-verified artifact through a replay-only tunnel: guacamole-common-js
  1.5.0's `SessionRecording(Blob)` path throws (`reading 'size'`) and left the player blank. Replay never
  opens a session or sends input. A recording whose hash matches but contains no display frames is reported
  `no_display_data` and is not served.
- **HTTP/HTTPS applications open in an isolated browser** (`infrastructure/browser-isolation`, applications
  with access mode `ISOLATED_BROWSER`). It is not a proxy: the application runs in a disposable Chromium inside
  a container, and the operator's browser only receives pixels (noVNC) and sends keyboard/mouse input. Cookies,
  storage and downloads never reach the operator's machine. Flow: launch validates the request, grant, application
  and session limit; the backend asks the isolation daemon to open **the registered destination only** (scheme,
  host, port and `start_path` from the application row; the client cannot pass a URL), and waits until the page
  is on the registered origin. The browser then redeems a one-time ticket on `/sessions/web/{id}/ws` (first frame).
  The backend authenticates to that session's x11vnc with a per-session random password, gives noVNC an
  already-authenticated stream, and relays it through an RFB message allowlist (`ClientMessageFilter`):
  SetEncodings is reduced to plain display encodings, and clipboard is dropped unless the application allows it.
  The per-second monitor (session, grant, request, user, application) ends the browser on termination, expiry
  or revocation, and the daemon deletes the profile and kills the session's processes.
- **Destination control.** Each session's Chromium uses a per-session egress proxy that allows only the
  registered `host:port`, connects to the IP resolved at launch (no DNS rebinding) and always refuses loopback,
  link-local, cloud metadata and multicast. Navigations or requests elsewhere (including Chromium's own calls to
  Google) are blocked and audited as `DESTINATION_DENIED`. Chromium policy (`policies.json`) disables
  certificate-error override, downloads, DevTools and non-proxied WebRTC UDP.
- **TLS fails closed.** The daemon validates the certificate before launching Chromium. An invalid certificate
  ends the launch with `TLS_VALIDATION_FAILED` unless the application has an explicit **key pin**
  (`tls_pin_sha256`, base64 SHA-256 of the server's SubjectPublicKeyInfo). Only that exact key is then
  accepted (Chromium `--ignore-certificate-errors-spki-list` plus the daemon's own check); any other
  certificate, including a different self-signed one, is refused. Compute the pin on the server itself,
  out of band, not from a network handshake:
  `openssl x509 -in <dashboard cert> -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
  The pin is the right approach for a self-signed lab dashboard; for production, install a certificate
  that validates normally and leave the pin empty.
- **Application credentials are never handled.** The operator signs in to the application in the isolated
  browser; SecurePAM does not store, inject or see those credentials.
- **Running it:** `cd infrastructure/browser-isolation && docker compose up -d --build`. Generate
  `.isolation_token` first (0600, git-ignored), e.g. `umask 077; openssl rand -hex 32 > .isolation_token`.
  Backend: `BROWSER_ISOLATION_ENABLED=true`, `BROWSER_ISOLATION_URL=http://127.0.0.1:6090`,
  `BROWSER_ISOLATION_TOKEN_FILE=<path to .isolation_token>`. The container is read-only, runs as UID 1000
  with all capabilities dropped, has an init process to reap Chromium's orphans, and publishes its API and
  VNC ports on 127.0.0.1 only. Never expose them.
- **Isolated-browser limits:** Chromium runs with `--no-sandbox`, so the container is the security boundary
  (do not loosen its settings). The VNC password registry lives in the backend process, so run one backend
  worker. Web sessions are **not recorded**, so an application that requires recording is refused rather
  than opened unrecorded. The watermark deters screenshots but cannot prevent them.
- **SIEM events.** Every audit event is also written as one redacted JSON line (`{"securepam": {...}}`; no
  tokens, passwords, tickets or credentials) to `SIEM_EVENT_LOG_PATH` (0600). To ship to Wazuh, use the real
  ingestion path, a Wazuh agent on the backend host reading that file, never the dashboard:
  `<localfile><log_format>json</log_format><location>/path/to/siem-events.json</location></localfile>` in the
  agent's `ossec.conf`, plus rules for the `securepam.action` values you want to alert on (e.g.
  `DESTINATION_DENIED`, `TLS_VALIDATION_FAILED`, `SESSION_TERMINATED`, `BROWSER_CLEANUP_FAILED`). An event is
  written before its database commit, so a rare rolled-back action can still appear in the file.
- The embedded terminal carries a persistent watermark (operator, session
  number, live UTC time). It deters and attributes screenshots; it cannot
  prevent screenshots or external capture.
- Sample assets/applications are not seeded (`SEED_SAMPLE_TARGETS=false`).
  To retire the old sample rows from an existing dev database:
  `cd backend && .venv/bin/python -m scripts.retire_sample_targets [--apply]`.

Not implemented: Keycloak/OIDC (DEV_MODE accounts only), OpenBao
rotation/dynamic secrets, Windows command telemetry, a web reverse proxy
(HTTP apps use the isolated browser instead), isolated-browser recording, a
Wazuh agent/rule pack (the JSON event file is produced; shipping it is a host
setup step), a recording-retention
sweep, and a background sweep for request-queue/JIT expiry (lazy today —
evaluated when something looks at the row; live SSH sessions are the
exception, being checked every second). The UI shows an honest
"planned" placeholder only for Risk Center, Users and Roles.
