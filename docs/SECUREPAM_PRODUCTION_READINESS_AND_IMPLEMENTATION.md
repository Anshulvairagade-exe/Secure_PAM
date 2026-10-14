# SecurePAM — Production readiness & implementation guide

Companion to `SECUREPAM_WAZUH_OPENBAO_KEYCLOAK_IMPLEMENTATION.md` (Wazuh TLS, first OpenBao/Keycloak pass).

**Status labels** used everywhere below:

| Label | Meaning |
|---|---|
| **[LOCAL ✔]** | Implemented and tested locally (unit/integration tests and/or the running local lab) |
| **[ISOLATED ✔]** | Proven against a disposable instance started for the test and destroyed afterwards |
| **[AWS]** | Needs your AWS account, credentials and resources; not executed here |
| **[APPROVAL]** | Needs your explicit approval or a manual action (e.g. reviewing a Terraform plan) |
| **[NOT IMPLEMENTED]** | Deliberately not built, or unsupported; the UI says so |

No secret values appear in this document. `<...>` are placeholders.

---

## 1. Architecture and trust boundaries

```
            HTTPS                    HTTPS (ALB, ACM)                 private
 Browser ─────────▶ SecurePAM UI ──▶ SecurePAM backend ──TLS──▶ AWS OpenBao (internal NLB → EC2, Raft/EBS, KMS seal)
    │                                   │   │  reader token: read on 3 exact paths
    │  OIDC (PKCE)                      │   │  writer token: create+update on 3 exact paths (admin provisioning only)
    └──────────▶ AWS Keycloak (ALB) ◀───┘   │
                 │ start --optimized         └── Keycloak Admin REST: audit reader, realm-management/view-events only
                 └── RDS PostgreSQL (private, encrypted, RDS-managed secret)

 Administrators ──SSM port-forward──▶ OpenBao UI (8200) / Keycloak admin (8080)   — never public
```

| Boundary | Control |
|---|---|
| Browser → backend | JWT (Keycloak) or DEV accounts locally; RBAC from SecurePAM's DB only; every privileged change audited. |
| Browser → OpenBao | **None.** The UI never receives an OpenBao token or a stored secret. "Open OpenBao Vault" is a plain link to the private UI; you sign in there yourself. |
| Backend → OpenBao | Reader identity (runtime) and an optional, separate writer identity (provisioning). Both short-lived, orphan, non-renewable, minted only through token roles. |
| Administrators → OpenBao | `userpass` administrator (least privilege), 8 h tokens; root is break-glass only. |
| Backend → Keycloak | `securepam-audit-reader` (client credentials), `view-events` only. |
| Keycloak admin | `/admin/*` blocked at the ALB except admin CIDRs; or SSM port-forward to the node. |

## 2. Local vs AWS separation

| Concern | Local lab (unchanged) | AWS |
|---|---|---|
| OpenBao | `bao server -dev` on 127.0.0.1:18200 (in-memory) — **never touched by this work** | `infrastructure/openbao/aws/` (Raft, TLS, KMS seal, UI on private listener) |
| Keycloak | `docker-compose.keycloak.yml` (`start-dev`, 127.0.0.1:8080, image `securepam-keycloak-mfa-audit:24.0`) | `infrastructure/keycloak/aws/` (Keycloak 24.0.5 `start --optimized`, RDS, ALB) |
| Backend secrets | `.env` / `backend/.env` | Secrets Manager → files (`*_FILE`) or env injected at start |
| Realm | lab realm in `keycloak_postgres_data` volume | fresh realm imported once from `infrastructure/keycloak/realm-import/securepam-realm.json` (no keys/users/secrets), then `configure-realm.py` |

Nothing moves local Keycloak data into AWS. A migration would need its own reviewed plan (users re-enrol TOTP; no export of hashes or seeds).

---

## 3. AWS OpenBao

### 3.1 What changed in this pass

| Change | Status |
|---|---|
| `ui = true` on the private TLS listener; no public listener | **[ISOLATED ✔]** UI served (`GET /ui/` 200), admin token lists mounts and reads KV metadata |
| Administrator identity: `userpass` + `securepam-admin` policy | **[ISOLATED ✔]** 18/18 verification checks (can/cannot matrix) |
| Token roles `securepam-app` (24 h) / `securepam-writer` (1 h): policy, orphan, non-renewable, max TTL pinned | **[ISOLATED ✔]** minting/rotation work with the admin identity, no root |
| Root escrow (`--escrow-root-arn`), retirement (`--retire-root --confirm-recovery-keys-custodied`), regeneration (`--generate-root`) | **[ISOLATED ✔]** retire → regenerate (both layers) → retire again |
| Terraform: EBS snapshot policy (DLM), audit log group with retention, health alarms, root-escrow secret shell, SSM UI port-forward output, `tfvars.example` | `fmt`/`validate`/`tflint` clean; **no plan/apply** (**[AWS]**) |

### 3.2 The three identities

| Identity | How obtained | Can | Cannot | Where it lives |
|---|---|---|---|---|
| **Emergency root** | `sys/init` on the new server | everything | — | 0600 file `~/.securepam/openbao-aws-root.txt` → escrow (Secrets Manager or offline) → **retired** |
| **Administrator** `securepam-admin` | `bao login -method=userpass username=securepam-admin` | KV CRUD under `secret/securepam/*`, UI browsing, read policies/mounts/auth/audit, Raft snapshot **save**, mint app/writer tokens **via roles**, lookup/revoke by accessor, start root generation (needs key quorum to finish), change own password | write policies, enable/disable auth or engines, change audit, orphan/arbitrary tokens, edit token roles, restore snapshots, seal, anything outside `secret/securepam/` | your password manager; tokens 8 h (max 12 h) |
| **Backend reader** `securepam-app` | `auth/token/create/securepam-app` | `read` on the 3 registered paths | everything else | Secrets Manager `<project>/openbao/app-token` → backend `OPENBAO_TOKEN` / `OPENBAO_TOKEN_FILE` |
| **Credential writer** `securepam-writer` | `auth/token/create/securepam-writer` | `create`+`update` on the 3 paths | read, list, delete, destroy, metadata, other paths, tokens | Secrets Manager `<project>/openbao/writer-token` → backend `OPENBAO_WRITER_TOKEN(_FILE)` only if integrated provisioning is wanted |

Registered paths (unchanged): `securepam/assets/win11-lab`, `securepam/assets/kali`, `securepam/assets/wazuh-dashboard`.

### 3.3 Prerequisites **[AWS]**
AWS CLI v2 + Session Manager plugin on your Mac; Terraform ≥ 1.6; an AWS principal allowed to create VPC-scoped resources (EC2, NLB, KMS, IAM roles, Route 53 records, Secrets Manager, DLM, CloudWatch); a VPC with ≥ 2 private subnets and NAT; a private hosted zone for the A record **and a public hosted zone for the same registered domain** (Let's Encrypt DNS-01); the `openbao-plugins` release checksum.

### 3.4 Deploy **[AWS] [APPROVAL]**
```bash
cd infrastructure/openbao/aws/terraform
cp terraform.tfvars.example terraform.tfvars        # fill in (git-ignored)
terraform init
terraform fmt -check && terraform validate
terraform plan -out tfplan                          # review: what is created, IAM statements, SGs, no public ingress
terraform show -no-color tfplan > tfplan.txt        # send/keep for approval
terraform apply tfplan                              # only after you approve the plan
```
Review checklist for the plan: no `0.0.0.0/0` ingress; NLB `internal = true`; instance has no public IP; IAM instance policy limited to the seal key, `_acme-challenge` TXT on the public zone, the audit log group, SSM; KMS deletion window 30 days; EBS encrypted; DLM targets only the Raft volume.

### 3.5 Bootstrap — first run, exactly once **[AWS]**
```bash
export OPENBAO_ADDR=https://<bao.ops.example.com>
# first run: initialises (recovery keys + root to ~/.securepam, mode 600), policies, roles,
# userpass + securepam-admin (password: hidden prompt, ≥16 chars, typed twice)
./infrastructure/openbao/aws/provision/provision.sh --seal awskms --bootstrap-admin
```
The run proves the administrator works (logs in, checks the can/cannot matrix, revokes that test token). It **never** re-initialises: an initialised server is detected and init is skipped.

Hand the recovery keys to their custodians (one per person; never in Git, chat or the same place as the root token).

### 3.6 Escrow and retire the root token **[AWS] [APPROVAL]**
Option A, Secrets Manager (restrict the secret's resource policy to the custodians' role):
```bash
./infrastructure/openbao/aws/provision/provision.sh --escrow-root-arn <terraform output root_escrow_secret_arn>
```
Option B, offline/private, without ever displaying it:
```bash
pbcopy < ~/.securepam/openbao-aws-root.txt   # copies without printing; paste into your password manager
pbcopy < /dev/null                            # clear the clipboard
```
Then retire it, only after the administrator works:
```bash
export OPENBAO_ADMIN_TOKEN="$(bao login -method=userpass -token-only username=securepam-admin)"   # hidden prompt
./infrastructure/openbao/aws/provision/provision.sh --retire-root --confirm-recovery-keys-custodied
```
`--retire-root` refuses unless the admin identity verifies, revokes the root token and removes its file.

### 3.7 Recovery — "I have no working root/admin token" **[ISOLATED ✔]**
Verified on OpenBao 2.7.1: the CLI's `bao operator generate-root` uses the **authenticated** endpoint, and the unauthenticated legacy endpoint is **disabled by default** (`disable_unauthed_generate_root_endpoints`).

| Situation | Procedure |
|---|---|
| Admin password forgotten, root escrowed | Use the escrowed root: `--reset-admin-password` (hidden prompt), then retire root again. |
| Root lost, admin works | Layer 1: as admin, `bao operator generate-root -generate-otp`, `-init -otp=…`, each custodian submits a recovery key (`-nonce=…`), `-decode=… -otp=…` → new root. Use, then `--retire-root`. |
| Root **and** admin lost | Layer 2 (last resort): over SSM, add `disable_unauthed_generate_root_endpoints = false` to the `listener "tcp"` stanza, restart the container (KMS auto-unseals), run `provision.sh --generate-root` (custodians type keys into hidden prompts; new root goes to a 0600 file, never shown), **remove the line and restart**, then `--reset-admin-password` / `--retire-root`. |
| Recovery keys lost too | A new root cannot be generated. Data remains readable by any still-valid token; otherwise restore is not possible. Keep custody records. |

Never re-initialise an existing server to "get a new token": that destroys access to all stored secrets.

### 3.8 Open the OpenBao UI from your Mac **[AWS]**
```bash
terraform -chdir=infrastructure/openbao/aws/terraform output -raw ui_port_forward_command | sh   # keeps running
echo "127.0.0.1 <bao.ops.example.com>" | sudo tee -a /etc/hosts      # once; makes the TLS name match
open https://<bao.ops.example.com>:8200/ui/
```
Sign in: **Method: Username**, user `securepam-admin`. Then **Secrets engines → secret/ → securepam/assets/** to see the credential paths; **Version history** and **metadata** per secret; **Create secret** for a registered path. Changes are in the audit log (CloudWatch `/<project>/bao-audit`; values HMAC-hashed). Set `OPENBAO_UI_URL=https://<bao.ops.example.com>:8200/ui/` on the backend so the Assets page's "Open OpenBao Vault" button points there.

### 3.9 Tokens: TTL, rotation, verification, revocation **[ISOLATED ✔]**
```bash
export OPENBAO_ADMIN_TOKEN="$(bao login -method=userpass -token-only username=securepam-admin)"
./infrastructure/openbao/aws/provision/provision.sh --rotate app        # daily (24 h TTL)
./infrastructure/openbao/aws/provision/provision.sh --rotate writer
OPENBAO_TOKEN="$(cat ~/.securepam/openbao-aws-app-token)" \
  ./infrastructure/openbao/aws/provision/provision.sh --verify-only --verify-writer
./infrastructure/openbao/aws/provision/provision.sh --push-secrets --app-secret-arn <arn> --writer-secret-arn <arn>
```
Rotation mints into a `.pending` file, verifies the replacement, swaps it in, and only then revokes the predecessor. A failed replacement is revoked and the working token kept. Emergency revocation: `bao token revoke -accessor <accessor from ~/.securepam/openbao-aws-state.json>`.

### 3.10 Backup, restore, monitoring **[AWS]**
- Daily encrypted EBS snapshots of the Raft volume (DLM, 14 kept by default) — crash-consistent, no token on the host.
- Before upgrades: `bao operator raft snapshot save pre-upgrade.snap` as the administrator (allowed); store it encrypted.
- Restore (break-glass, root): new node from Terraform → `bao operator raft snapshot restore` (`snapshot-force` needs root) → KMS unseals → `provision.sh` (idempotent) → `--verify-only`.
- Alarms: NLB unhealthy target (sealed/down/TLS) and EC2 status check; optional SNS via `alarm_sns_topic_arn`.
- Single node: an AZ outage makes credential checkout fail closed. HA = 3 Raft voters.

---

## 4. AWS Keycloak and MFA

### 4.1 Components (`infrastructure/keycloak/aws/`)
| Piece | Notes | Status |
|---|---|---|
| `Dockerfile` | Keycloak **24.0.5** (provider SPI line 24.0.0), `start --optimized --import-realm`, health/metrics built in, impersonation disabled, sanitized realm baked in | **[ISOLATED ✔]** built and run in production mode with a disposable PostgreSQL |
| `terraform/` | ECR (immutable, scan on push), RDS PostgreSQL 16 (private, encrypted, `rds.force_ssl`, 14-day backups, deletion protection, final snapshot, **RDS-managed master secret**), private EC2 node (IMDSv2, SSM, no SSH), ALB with ACM cert + TLS 1.2/1.3 policy, `/admin/*` only from admin CIDRs, `/health*`/`/metrics*` never forwarded, Route 53, log group, alarms | `fmt`/`validate`/`tflint` clean; **[AWS] [APPROVAL]** |
| `terraform/user-data.sh` | renders `/opt/keycloak/keycloak.env` (0600) from Secrets Manager; hourly refresh restarts Keycloak when the RDS-rotated password changes | rendered + `bash -n` |
| `configure-realm.py` | idempotent hardening + verification (below) | **[ISOLATED ✔]** 19/19 PASS, re-run idempotent |

### 4.2 Deploy **[AWS] [APPROVAL]**
```bash
# 1. image
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
docker build -f infrastructure/keycloak/aws/Dockerfile -t <ecr_repository_url>:<git-sha> .
docker push <ecr_repository_url>:<git-sha>
# 2. bootstrap admin secret (value from a file, never argv/history)
umask 077; printf '{"username":"kc-bootstrap","password":"%s"}' "$(openssl rand -base64 30)" > /tmp/kcadmin.json
aws secretsmanager put-secret-value --secret-id <bootstrap_admin_secret_arn> --secret-string file:///tmp/kcadmin.json; rm -P /tmp/kcadmin.json
# 3. infrastructure (review the plan first)
cd infrastructure/keycloak/aws/terraform && cp terraform.tfvars.example terraform.tfvars
terraform init && terraform validate && terraform plan -out tfplan && terraform apply tfplan
```
(Steps 1–2 can run before `apply` creates the ECR repo only if the repo exists: run `terraform apply -target=aws_ecr_repository.keycloak -target=aws_secretsmanager_secret.bootstrap_admin` first, also after approval.)

### 4.3 Harden + verify the realm, generate fresh audit-reader credentials **[AWS]**
```bash
terraform -chdir=infrastructure/keycloak/aws/terraform output -raw admin_port_forward_command | sh   # private admin path
KEYCLOAK_ADMIN_USER=kc-bootstrap python3 infrastructure/keycloak/aws/configure-realm.py \
  --url https://<auth.ops.example.com> --frontend-url https://<securepam.ops.example.com> \
  --secret-arn <audit_reader_secret_arn>                 # admin password: hidden prompt
```
It enforces: listener `securepam-otp-audit` + event storage + `LOGIN_ERROR`; `sslRequired=all`; brute-force protection; TOTP policy (SHA1, 6 digits, 30 s, no reuse — Google/Microsoft Authenticator compatible); `CONFIGURE_TOTP` as a default action (**every new user must enrol**); OTP step in the browser flow; `securepam-app` limited to your frontend origin with PKCE S256 and no password grant; reader = `view-events` only, then a **new** secret straight into Secrets Manager and a proof (events 200, users 403, clients 403). After that, create a personal admin in the master realm and disable the bootstrap admin.

### 4.4 How users enrol their authenticator
1. Open SecurePAM → **Sign in** (redirects to Keycloak).
2. Enter username + password.
3. **Mobile Authenticator Setup** appears (first sign-in only): open Google Authenticator / Microsoft Authenticator / 1Password / Authy, choose *Add account → Scan QR code*, scan the code (or "Unable to scan?" for the text key).
4. Type the 6-digit code shown in the app, optionally name the device, **Submit**.
5. From now on every sign-in asks for the current code. Manage/replace devices: Settings → Profile → "Keycloak account security".

A wrong code is rejected and becomes a `SECUREPAM_MFA_FAILURE` log line + an MFA-failure security event in SecurePAM.

### 4.5 Backend MFA sync (AWS)
Backend configuration (names only):
`KEYCLOAK_URL=https://<auth…>`, `KEYCLOAK_REALM=securepam`, `KEYCLOAK_AUDIT_CLIENT_ID=securepam-audit-reader`,
`KEYCLOAK_AUDIT_CLIENT_SECRET` **or** `KEYCLOAK_AUDIT_CLIENT_SECRET_FILE=<0600 file rendered from the secret>`,
`KEYCLOAK_MFA_SYNC_ENABLED=true`, `KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS=60`, `KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS=1`.
`*_FILE` works for host-run and container-run backends; a group/world-readable file is refused at startup.
The backend's network path to `/admin/realms/securepam/events` must be in `admin_cidr_blocks` (or inside the VPC via the backend SG).

### 4.6 Acceptance results

| # | Test | Local lab (start-dev) | Production mode (isolated) |
|---|---|---|---|
| 1 | invalid OTP → `SECUREPAM_MFA_FAILURE` | ✔ | ✔ (1 new line) |
| 2 | backend imports it | ✔ imported 1 | ✔ imported 1 (isolated DB migrated from scratch) |
| 3 | security-event feed + dashboard metric | ✔ feed + metric 0→1 | (same code path; DB count) |
| 4 | valid OTP still signs in | ✔ tokens issued | ✔ tokens issued |
| 5 | repeated sync, no duplicates | ✔ 0 / already_imported 1 | ✔ 0 / already_imported 1 |
| 6 | wrong password not counted | ✔ | ✔ |
| 7 | reader cannot read users/clients | ✔ 403 / 403 | ✔ 403 / 403 |
| 8 | no client secret / OTP seed in logs or responses | ✔ | ✔ (0 matches in Keycloak logs) |
| — | against real AWS | | **[AWS]** run `configure-realm.py`, then the same flow |

`view-events` also allows reading admin events (no narrower Keycloak role exists); admin-event recording is off in this realm. Imported events show the Keycloak user ID; names would need `view-users` — not granted.

---

## 5. Assets and credentials

### 5.1 Integrated workflow (preferred) **[LOCAL ✔] [ISOLATED ✔]**
**Assets → New Asset → Credential: "Provision now in OpenBao"** → choose an **approved reference** (dropdown; references already bound to another asset are disabled) → username → password (masked) → **Create Asset**.

Server side, in one transaction (savepoint):
1. Admin check (`vault:manage`); provisioning configured? (else **503 PROVISIONING_NOT_CONFIGURED**, nothing created).
2. Reference name must be in `ASSET_CREDENTIAL_SECRET_NAMES` and not bound elsewhere (the browser never sends a path; `vault_path` in the payload is rejected).
3. Asset row created → secret written by the **writer** identity → **read back by the reader** identity and compared in constant time → binding (`vault_refs`) written → commit + audit `CREDENTIAL_PROVISIONED` (who, asset, path, version; never the value).
4. Any failure rolls back the asset and binding. The response names the stage (`validate|configure|write|verify`), a recovery hint, and, if a version was written but not verified, that version number. The **key icon** on an asset row is the retry/rotation path.

Live proof against a real OpenBao 2.7.1 with the repository's policies: create → v1, rotate → v2, a reference outside the writer policy → `WRITE_DENIED` (OpenBao enforces the policy even if the allowlist were widened).

The development `mock` provider never accepts real credentials: the page shows **"Credential provisioning is not configured"**.

### 5.2 OpenBao UI option
**Open OpenBao Vault** (Assets page banner) opens `OPENBAO_UI_URL` in a new tab. No token is attached; the button is disabled when the URL is not configured. Store the secret at a registered path, then bind it (Vault references page / `PUT /api/v1/assets/{id}/credential-ref`).

### 5.3 Adding a new credential reference **[APPROVAL]**
Add the exact path to `aws/policies/securepam-app.hcl` (read) and `securepam-writer.hcl` (create, update); add the name to `ASSET_CREDENTIAL_SECRET_NAMES`; re-run `provision.sh` (with root, policies are written) and `--verify-only`.

---

## 6. Admin Users and Settings

### 6.1 Users **[LOCAL ✔]**
List with search/state/role filters and pagination; detail (roles, effective permissions, last sign-in IP, failed sign-ins, live sessions); **Add user**; **Edit profile**; assign/remove roles; deactivate/reactivate; view/terminate sessions.

| Rule | Enforcement |
|---|---|
| Create needs `users:create`, edits `users:update` (ADMIN) | server-side; operator/approver/auditor get 403 (tested, incl. trying to create an ADMIN) |
| Keycloak mode: user = Keycloak user ID (UUID); no password accepted | server-side; DEV mode: local account with ≥ 12-char password, stored as a hash only |
| You cannot change your own roles/state or relink your identity; the last active admin cannot be removed/deactivated | server-side |
| A linked Keycloak identity is never re-pointed | 409; deactivate + create instead |
| Everything audited (`USER_CREATED`, `USER_UPDATED`, `ROLE_*`, `USER_DEACTIVATED`) without secrets | tested |

The MFA column says **not enforced (dev)** for development accounts instead of trusting the seeded flag.

### 6.2 Settings **[LOCAL ✔]**
Every card shows its scope:

| Setting | Scope | Editable |
|---|---|---|
| Theme (Light/Dark/System) | Your browser (`localStorage`) | yes |
| Profile & sign-in, MFA provider, link to Keycloak account security | Deployment | read-only (MFA is managed in Keycloak) |
| Concurrent sessions per user | Application · persisted (`app_settings`, audited) | `settings:update` |
| Risk detection thresholds | Application · persisted (audited) | `risk:manage` |
| Integrations & live service health | Deployment (live probe) | read-only |
| MFA-failure import, SIEM forwarding, secret provider, credential provisioning, OpenBao UI link, recording storage/retention | Deployment | read-only |
| Notifications | — | **[NOT IMPLEMENTED]** (no delivery channel; shown as such) |

No settings API returns a secret.

---

## 7. Sessions, recordings, logs

| Session type | Recording | Replay | Integrity |
|---|---|---|---|
| SSH | asciicast v2, server-side | Recording Center player | SHA-256 stored at finalization; re-verified before every stream (served only if it matches) |
| RDP | Guacamole session recording | Recording Center player | same |
| Isolated browser (HTTP/HTTPS) | **Recording unavailable** | none (no fake player) | launch, egress denials and end are in the audit log; with "Recording required" set, launches are refused |

**Known failures fixed** **[LOCAL ✔]**. `test_ending_grant_ends_its_live_sessions[revoke|expire]` failed because ending a JIT grant used to mark a live recording **COMPLETED by assertion**, while the newer termination code (correctly) only lets the gateway mark it complete after flushing and hashing the artifact. If no gateway ever did, the row stayed `RECORDING` forever. Fix: the grant end no longer declares completion; a **recording reconciler** (every 60 s) marks recordings of ended sessions that are still unfinalized after 120 s (longer than the gateway's 30 s settle window) as **FAILED** with an audited reason (`RECORDING_NOT_FINALIZED` / `RECORDING_NOT_STARTED`); it never marks anything COMPLETED. Regression test covers: inside the grace window nothing changes; afterwards FAILED + audit; a gateway-finalized (hashed) recording stays COMPLETED; idempotent.

Admin termination, the per-user session view, transcripts and the audit log (filters/search) are unchanged and remain role-checked (`recordings:read`, `audit:read`, `sessions:terminate`). APIs never return filesystem paths or storage credentials.

---

## 8. Risk Center **[LOCAL ✔]**

### 8.1 Data sources
- `audit_logs` (SecurePAM's own events), `risk_events` (the deterministic risk engine's per-request evaluations, with factors), `sessions`.
- `risk_findings` (new table, migration `d4e5f6a7b8c9`): one row per issue, deduped by fingerprint, with evidence references, status lifecycle and remediation.
- External sources (scanner, SIEM correlation) via `POST /api/v1/risk/findings/ingest` (admin; `source`, `external_id`, `title`, `description`, `severity`, `remediation`, `observed_at`, optional `asset_id`/`application_id`, `evidence`). The built-in source name is reserved. **Nothing external is connected yet** — that is the contract a real source must call.

### 8.2 Rules (deterministic; 30-day look-back; evaluated every 5 min or "Evaluate now")
| Rule | Severity | Auto-resolves when |
|---|---|---|
| MFA_FAILURES per identity | HIGH if ≥ threshold (default 3) within 60 min, else LOW | — |
| LAUNCH_DENIALS per user | MEDIUM if ≥ threshold (default 5) within 60 min | — |
| CREDENTIAL_DENIED per asset | HIGH | a later successful retrieval |
| CREDENTIAL_FAILED per asset | MEDIUM | a later successful retrieval |
| CREDENTIAL_REF_BROKEN per asset | MEDIUM | the latest check passes |
| RECORDING_FAILED per recording | HIGH | — |
| TLS_VALIDATION per application | MEDIUM | a later successful launch |
| EGRESS_BLOCKED per application | LOW | — |
| HIGH_RISK_ACCESS per user+target | MEDIUM (engine CRITICAL) / LOW (engine HIGH) | — |

New evidence after a resolution **reopens** a finding. Status changes (Acknowledge/Resolve/Reopen) need `risk:manage`, are audited with before/after and an optional note. There is no aggregate "posture score": counts are shown by severity and status, and the risk engine's own scores are shown as a distribution.

### 8.3 What the page shows
Open findings by severity (clickable filters), new findings per day (stacked by severity, empty days drawn empty), the access-request risk distribution, filters (severity, status, rule, period, search, asset/application via link), a prioritized table, and a detail view with evidence records (linked audit events), related asset/application/session/user, and remediation. Data source and last-evaluated time are always visible. Tests assert the displayed counts equal the underlying rows.

---

## 9. Frontend design and theme **[LOCAL ✔]**
- Light and dark are both complete palettes: every surface, border, text grey and accent-text colour is a CSS variable swapped by `html.dark`, so all pages, tables, dialogs, forms, badges and session panels follow the theme. Terminals/players stay dark by design (`surface-terminal`).
- First visit follows the OS; an explicit choice persists in `localStorage` (`securepam.theme`). `public/theme-init.js` applies it **before first paint** (no flash; same-origin file, CSP-friendly).
- Shell: grouped sidebar (Overview, Access, Inventory, Oversight, Administration), header with section name, theme toggle, account menu (Escape/outside click closes). Removed decorative controls that did nothing (search box without search, notification bell without notifications, a hard-coded "DEV_MODE" footer, an unverified "MFA" badge).
- Accessibility: dialogs have `role="dialog"`, `aria-modal`, labelled titles, Escape to close; radio-group semantics on the theme control; visible `focus-visible` rings; text colours chosen for WCAG AA contrast in light mode.

---

## 10. Environment variables (names only)

**Backend:** `ENVIRONMENT`, `DEV_MODE`, `SECRET_KEY`, `DATABASE_URL`, `REDIS_URL`,
`KEYCLOAK_URL`, `KEYCLOAK_INTERNAL_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`,
`KEYCLOAK_AUDIT_CLIENT_ID`, `KEYCLOAK_AUDIT_CLIENT_SECRET` | `KEYCLOAK_AUDIT_CLIENT_SECRET_FILE`,
`KEYCLOAK_MFA_SYNC_ENABLED`, `KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS`, `KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS`,
`SECRET_PROVIDER`, `OPENBAO_ADDR`, `OPENBAO_CA_CERT`, `OPENBAO_MOUNT_POINT`, `OPENBAO_SECRET_PATH_PREFIX`,
`OPENBAO_TOKEN` | `OPENBAO_TOKEN_FILE`, `OPENBAO_WRITER_TOKEN` | `OPENBAO_WRITER_TOKEN_FILE`, `OPENBAO_UI_URL`,
`ASSET_CREDENTIAL_SECRET_NAMES`, `APPLICATION_CREDENTIAL_SECRET_NAMES`, `SIEM_EVENT_LOG_PATH`,
`BROWSER_ISOLATION_*`, `RECORDING_STORAGE_PATH`, `RECORDING_RETENTION_DAYS`.

**Provisioner (operator shell):** `OPENBAO_ADDR`, `OPENBAO_ADMIN_TOKEN`, `OPENBAO_TOKEN` (verify), `OPENBAO_ADMIN_PASSWORD` (non-interactive bootstrap only), `OPENBAO_CRED_PASSWORD` (non-interactive credential only), `SECUREPAM_APP_SECRET_ARN`, `SECUREPAM_WRITER_SECRET_ARN`, `SECUREPAM_ROOT_ESCROW_SECRET_ARN`.

**Keycloak node (rendered at boot):** `KC_DB_URL`, `KC_DB_USERNAME`, `KC_DB_PASSWORD`, `KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD`, `KC_HOSTNAME`, `KC_HOSTNAME_ADMIN`, `KC_HOSTNAME_STRICT`, `KC_HOSTNAME_STRICT_HTTPS`, `KC_HTTP_ENABLED`, `KC_PROXY_HEADERS`.

---

## 11. Rollback

| Area | Rollback |
|---|---|
| Frontend theme/pages | revert the frontend files; no data involved |
| Risk Center | `alembic downgrade c3d4e5f6a7b8` drops `risk_findings` (findings are re-derivable) |
| Integrated provisioning | unset `OPENBAO_WRITER_TOKEN` → fails closed; existing bindings unaffected |
| Recording reconciler | it only sets FAILED on long-dead, unfinalized recordings; nothing is deleted |
| OpenBao/Keycloak AWS | `terraform destroy` only after snapshots; RDS final snapshot is mandatory; never delete the KMS key during its window |

## 12. Tested vs. operator steps (summary)

| Item | Status |
|---|---|
| OpenBao: init, admin identity, roles, rotation, writer create/update, verify 50/50, UI, snapshot, retire/regenerate root (both layers), audit without plaintext secrets | **[ISOLATED ✔]** |
| OpenBao/Keycloak Terraform | `fmt` + `validate` + `tflint` ✔; plan/apply **[AWS] [APPROVAL]** |
| Keycloak prod image + realm hardening + full MFA chain | **[ISOLATED ✔]** |
| Integrated asset credential provisioning | **[LOCAL ✔]** + **[ISOLATED ✔]** against real OpenBao |
| Users / Settings / Risk Center / theme / recording honesty | **[LOCAL ✔]** (tests + screenshots in both themes) |
| AWS deployment, real tokens, real UI login over SSM, real Keycloak on AWS | **[AWS]** — not performed; nothing here is claimed live |
| Notifications | **[NOT IMPLEMENTED]** |
