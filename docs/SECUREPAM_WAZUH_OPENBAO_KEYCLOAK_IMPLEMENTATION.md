# SecurePAM — Wazuh HTTPS, AWS OpenBao and Keycloak MFA audit: implementation

Status legend used throughout: **[TESTED LIVE]** observed on the running system on 2026-10-15;
**[TESTED]** automated tests / throwaway instances; **[OPERATOR]** requires an AWS or host action
that has not been performed. No secret values appear in this document; `<...>` marks placeholders.

---

## 1. Architecture and trust boundaries

```
 Browser ──HTTPS──▶ SecurePAM frontend ──▶ SecurePAM backend (FastAPI)
                                              │   │      │
            noVNC over the backend relay ◀────┘   │      └── Keycloak Admin REST (audit-reader, view-events)
                                                  │              ▲ persisted events
   isolated-browser container (daemon.py)  ◀──────┘              │
     Chromium ─▶ per-session egress proxy ─▶ registered host:port only (pinned IP, TLS verified)
                                                                  Keycloak (securepam realm)
   AWS OpenBao (private, TLS, KMS seal) ◀── backend app token (read-only, exact paths)    └ securepam-otp-audit listener
        ▲ writer token (create+update, exact paths) — operator CLI only                     (logs SECUREPAM_MFA_FAILURE)
```

| Boundary | Control |
|---|---|
| User → isolated app | Backend builds the URL from the registration (`extra="forbid"`, IDs only); JIT grant + active request required; every launch/denial audited. |
| Isolated browser → network | Egress proxy allows only the registered `host:port`, connects to the IP pinned at session start, never loopback/link-local/metadata. |
| Isolated browser → TLS | Full chain + host-name/IP validation always. Private CAs only through a name-constrained managed policy. SPKI pin enforced **in addition**. No certificate-error overrides exist. |
| Backend → OpenBao | App token: `read` on exact registered paths, nothing else. Writer token: never in the backend. |
| Backend → Keycloak | `securepam-audit-reader` service account: `realm-management/view-events` only. |
| Keycloak → backend | Nothing pushes: the listener only logs; the backend pulls persisted events. |

---

## 2. Wazuh HTTPS certificate: diagnosis and remediation

### Root cause [TESTED LIVE]

`https://3.104.196.100/app/login` (Wazuh 4.14.8, Ubuntu 24.04) served the installer's default certificate:

| Check | Finding |
|---|---|
| Issuer | `OU=Wazuh, O=Wazuh, L=California` — the **private** Wazuh root CA from `wazuh-certs-tool` |
| Chain sent | Leaf only (`Verify return code: 21 unable to verify the first certificate`) → Chrome `NET::ERR_CERT_AUTHORITY_INVALID` |
| SAN | `IP Address:127.0.0.1` **only** → even with the CA trusted, validation for `3.104.196.100` fails (IP mismatch) |
| Validity | Not expired (2026-09-24 → 2036-09-21) |
| Ports | TLS-only on 443 (plain HTTP to 443 → empty reply / `ERR_EMPTY_RESPONSE`); 80 closed |

The previous gateway design compensated with the pin *instead of* validation: `tls_check` used
`CERT_NONE` + `check_hostname=False` when a pin was set, and Chromium was launched with
`--ignore-certificate-errors-spki-list=<pin>`. That is a certificate-error override and was removed.

### What was changed

**Gateway (`infrastructure/browser-isolation/`)** [TESTED LIVE]
- `daemon.py` `tls_check`: always `CERT_REQUIRED` + host-name/IP validation; roots = public store, plus
  operator private CAs **whose constraints cover the host**; every SAN in the leaf must be inside the
  constraint (mirrors Chromium's RFC 5280 enforcement, see troubleshooting); pin compared afterwards.
- Chromium: no certificate flags at all. Trust comes from the managed policy
  `CACertificatesWithConstraints` (Chromium 131 on Alpine 3.20 supports it).
- `trust_policy.py` (new): writes `trust/chromium-policy.json` from a CA PEM. Refuses non-CA certs,
  files containing a private key, expired CAs, and missing/over-broad constraints (single-label or
  wildcard DNS, IPv4 wider than /24, IPv6 wider than /64).
- `compose.yml` mounts `./trust` read-only at `/etc/securepam/trust`; the image symlinks the policy
  into `/etc/chromium/policies/managed/`. `trust/*.json` is git-ignored.
- Backend `TLS_VALIDATION_FAILED` message updated (no longer implies a pin can substitute for trust).

**Wazuh host (performed over SSH with the owner's approval)** [TESTED LIVE]
- Backup: `/root/wazuh-dashboard-certs-backup-20261014T183406Z` (plus an earlier one from a rolled-back attempt, `…182943Z`).
- New dashboard leaf signed by the **existing** Wazuh root CA, **reusing the existing dashboard key**
  (so the registered `tls_pin_sha256` stays valid): `SAN = IP:3.104.196.100` only, `CA:FALSE`,
  `keyUsage digitalSignature,keyEncipherment`, `extendedKeyUsage serverAuth`, SKI/AKI, 365 days
  (expires 2027-10-14). `127.0.0.1` was deliberately dropped: the CA is constrained to
  `3.104.196.100/32`, and an out-of-constraint SAN makes Chromium reject the whole certificate.
- Installed with the original owner/mode (`wazuh-dashboard`, 0400), `wazuh-dashboard` restarted,
  verified on the host with `openssl s_client -verify_ip 3.104.196.100 -CAfile root-ca.pem` and an
  HTTP 200 from `curl --cacert`. Automatic rollback on failure (it was exercised once: a too-early
  readiness check saw HTTP 503 during dashboard start-up and restored the backup cleanly).
- Only the public `root-ca.pem` left the host; the CA private key did not.

**Isolated-browser trust** [TESTED LIVE]
```bash
cd infrastructure/browser-isolation
python3 trust_policy.py --ca trust/wazuh-root-ca.pem --permit-ip 3.104.196.100
docker compose up -d --force-recreate
```
Trusted CA: `L=California,O=Wazuh,OU=Wazuh`, SHA-256 `b6318c89…ba00246`, limited to `3.104.196.100/32`.

### Verification results

| Test | Where | Result |
|---|---|---|
| Wazuh login page loads, no privacy warning | isolated browser (daemon) | **READY**, title `Wazuh`, login form rendered (screenshot) |
| Same, through SecurePAM API (`POST /sessions/web/launch`, operator + approved request) | full stack | **201** in 3.7 s, `SESSION_PREPARED` audited, page on `/app/login` |
| Mouse + keyboard | real Wazuh page via VNC | click focused *Username*, dummy text typed; **nothing submitted, no credentials used** |
| Wazuh CA + registered pin | runtime `tls_check` | ACCEPTED |
| Wrong pin | runtime | REJECTED |
| Public roots only (no private CA) | runtime | REJECTED |
| CA constrained to another IP | runtime | REJECTED |
| Expected IP ≠ certificate SAN | runtime + `openssl -verify_ip` | REJECTED (`IP address mismatch`) |
| Hermetic lab: private CA + leaf, wrong pin, name outside constraints, unrelated CA, `169.254.169.254`, `127.0.0.1` | throwaway instances of the new image | accepted only the intended case; metadata/loopback `DESTINATION_BLOCKED` |
| Unit tests | `backend/tests/test_web_isolation.py` | 63 passed |

Egress denials seen during real sessions were Chromium's own background calls
(`accounts.google.com`, `optimizationguide-pa.googleapis.com`) — correctly blocked, no effect on the page.

### Operator follow-ups for this lab
- **Elastic IP**: the certificate names `3.104.196.100`. If the EC2 public IP changes, reissue (same
  procedure) and regenerate the trust policy. A DNS name is the long-term fix (no domain purchase was
  required for this temporary lab).
- **CA key hygiene**: `/home/ubuntu/wazuh-install-files/` (root-only) holds `root-ca.key` and
  `wazuh-passwords.txt`. Move the CA key offline when not issuing certificates.
- **Renewal**: the leaf expires 2027-10-14; reissue before then (key reuse keeps the pin valid).
- Rollback: `sudo rm -rf /etc/wazuh-dashboard/certs && sudo cp -a /root/wazuh-dashboard-certs-backup-20261014T183406Z /etc/wazuh-dashboard/certs && sudo systemctl restart wazuh-dashboard`
  (then the isolated browser will again fail closed with `TLS_VALIDATION_FAILED`, as it should).

---

## 3. Local versus AWS OpenBao

| | Local lab (`bao server -dev` on 127.0.0.1:18200, and the compose `openbao` profile) | AWS (`infrastructure/openbao/aws/`) |
|---|---|---|
| Storage | in-memory | Raft on encrypted EBS |
| TLS | none (loopback) | Let's Encrypt, full chain, TLS ≥ 1.2 |
| Seal | dev auto-unseal | AWS KMS via the `awskms` plugin |
| Identities | dev root + `securepam-read` | bootstrap/root (recovery only), `securepam-app`, `securepam-writer` |
| This work | **untouched** (never restarted, never written, its token never used) | prepared, validated, exercised on throwaway 2.7.1 servers; **not deployed** |

---

## 4. AWS prerequisites and deployment **[OPERATOR — not deployed]**

Not available from this workstation: AWS CLI, Terraform, AWS credentials. Nothing was applied.

Prerequisites: VPC with private subnets (2+ AZs) and NAT; a hosted zone for the A record (private is
fine); a **public** hosted zone for the same registered domain (ACME TXT only); a name under a
registered domain (e.g. `bao.ops.example.com` — `.internal`/`.local` are rejected by a variable
validation because Let's Encrypt cannot issue for them); backend security groups; Let's Encrypt email;
the `openbao-plugins` release checksum (and confirm the asset name used in `user-data.sh`).

```bash
cd infrastructure/openbao/aws/terraform
terraform init
terraform fmt -check && terraform validate          # [TESTED] passes (Terraform 1.9.8, AWS provider >= 5)
terraform plan -out tfplan \
  -var vpc_id=<vpc-…> -var 'private_subnet_ids=["<subnet-a>","<subnet-b>"]' \
  -var route53_zone_id=<private-zone> -var acme_public_zone_id=<public-zone> \
  -var dns_name=<bao.ops.example.com> -var 'allowed_backend_security_group_ids=["<sg-…>"]' \
  -var certbot_email=<ops@example.com> -var awskms_plugin_sha256=<sha256>
# review the plan, get approval, then:
terraform apply tfplan
```

Defects fixed in the Terraform/bootstrap before any deployment (each would have broken first boot):

| Defect | Fix |
|---|---|
| `data.aws_subnet.first.available_zone` (no such attribute) | `availability_zone` |
| Inline SG rules referencing each other (bao ↔ nlb) → dependency cycle | separate `aws_vpc_security_group_*_rule` resources |
| `${PLUGIN_VER}`/`${PLUGIN_SHA}` inside `templatefile` → render error | escaped `$${…}` |
| `/dev/sdf` does not exist on Nitro; volume attaches after boot | wait for `/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_<vol>` |
| Listener on the private IP inside a bridged container | `--network host` |
| `server -config=<file>` + entrypoint's `-config=/openbao/config` → config loaded twice | `server` only |
| Data dirs root-owned 0700, server runs as uid 100 | `chown 100:1000` |
| DNS-01 against a private zone / `.internal` name cannot succeed | public ACME zone + name validation; IAM limited to the `_acme-challenge` TXT record |
| Renewal never reached `/openbao/tls`; leaf-only cert | certbot deploy hook installs **fullchain** + key, restarts OpenBao; `certbot-renew.timer` enabled |
| `al2023-ami-*` also matches minimal AMIs | `al2023-ami-2023.*` |

Rendered user-data passes `bash -n`; rendered `bao-config.hcl` was checked against the 2.7.1 binary.

---

## 5. OpenBao: initialization, seal, policies, identities, rotation, audit, backup

### Server configuration (`aws/bao-config.hcl`) — verified against OpenBao 2.7.1 [TESTED]
- 2.7.1 has **no built-in `awskms` seal** (`unknown wrapper: awskms`): the plugin is required, and it
  needs `plugin_directory` plus a **relative** `command` (`plugin directory not configured` otherwise).
- `disable_mlock` is an unknown field in 2.x (mlock support was removed) — removed.
- Audit devices **cannot be enabled through the API** in 2.x ("use declarative, config-based audit
  device management") — now declared in `bao-config.hcl` (`audit "file" "file"`), shipped to CloudWatch.

### Provisioner (`provision/provision.sh` → `backend/scripts/openbao_aws_provision.py`)
Fixed defects, each found by running it against a real throwaway 2.7.1 server:

| Defect | Effect before | Fix |
|---|---|---|
| `provision.sh` not executable; `REPO_ROOT` one level short | could not start | `chmod +x`; `../../../..` |
| Admin token required before init | a new server could never be initialized | init allowed without one; the new root token (0600 file) is used for that run only |
| awskms init sent `secret_shares` | rejected by auto-unseal seals | `recovery_shares`/`recovery_threshold` |
| Token reuse looked up an accessor on `/auth/token/lookup` | **every rerun minted new live tokens** | `/auth/token/lookup-accessor` |
| Audit device created via API (and with a trailing `/`) | always failed on 2.x | verify the declarative device; fail with instructions if absent |
| Rotation wrote the replacement over the live token file before verifying | failed rotation lost the working token | mint to `.pending`, verify, then atomic swap; failed replacement is revoked |
| Verifier hard-coded the lab policy `securepam-read` | AWS `--verify-only` and app rotation always failed | `policy_name=securepam-app` |
| Writer rotation verified with read checks | always failed | new `verify_writer` (exact `create+update`, real denials) |
| Writer policy `update` only | **first write of a credential: HTTP 403** (verified) | `["create", "update"]` |
| Intermediate states printed as FAIL | successful first run exited 1 | reported as detected state |

Live run on a throwaway Raft/Shamir 2.7.1 server [TESTED]: init → unseal → KV v2 → declarative audit
(19 HMAC'd entries, no plaintext tokens) → policies → app (24 h) and writer (1 h) non-renewable orphan
tokens, 0600 files, accessors only in state → reruns reuse tokens → `--verify-only --verify-writer`
**50/50 PASS** with unstored paths reported as PENDING → writer **create (v1)** then **update (v2)**
→ app token reads the secret (field names only) → `--rotate app` / `--rotate writer` (replacement
verified, predecessor revoked HTTP 204) → 50/50 PASS again → leak scan of all output and state: 0 hits.
The throwaway server and its files were destroyed afterwards.

Writer token, tested live: create/update on registered paths 200; read, list, delete, destroy,
metadata, unregistered path, token creation: all **403**.

### Identities and TTLs
| Identity | Policy | TTL | Where it lives |
|---|---|---|---|
| bootstrap/root | — | until revoked | `~/.securepam/openbao-aws-root.txt` (0600) → custody, then revoke |
| backend app | `securepam-app` (read on 3 exact paths) | 24 h, non-renewable, orphan | 0600 file → Secrets Manager → backend `OPENBAO_TOKEN` |
| credential writer | `securepam-writer` (create+update on 3 exact paths) | 1 h, non-renewable, orphan | 0600 file / Secrets Manager; operator only |

### Operator sequence [OPERATOR]
```bash
export OPENBAO_ADDR=https://<bao.ops.example.com>
./infrastructure/openbao/aws/provision/provision.sh --seal awskms           # first run initialises; recovery keys + root to ~/.securepam (0600)
export OPENBAO_ADMIN_TOKEN="$(cat ~/.securepam/openbao-aws-root.txt)"      # or a narrower admin token
OPENBAO_TOKEN="$(cat ~/.securepam/openbao-aws-app-token)" \
  ./infrastructure/openbao/aws/provision/provision.sh --verify-only --verify-writer \
  --allow-unstored win11-lab --allow-unstored kali --allow-unstored wazuh-dashboard
./infrastructure/openbao/aws/provision/provision.sh --push-secrets --app-secret-arn <arn> --writer-secret-arn <arn>
./infrastructure/openbao/aws/provision/provision.sh --rotate app            # daily (24 h TTL); verify-then-revoke
```
Backup: `bao operator raft snapshot save` to an encrypted, versioned, object-locked S3 bucket; restore
on a new node from Terraform, KMS unseals, rerun the provisioner, `--verify-only`. Single node: one AZ
failure makes secrets unavailable and session launches fail closed; HA needs 3/5 Raft voters.
Never delete the KMS key while any snapshot may need restoring.

---

## 6. Provisioning the Wazuh credential reference [OPERATOR]

Do this only after §5's `--verify-only` passes against the deployed, TLS-trusted AWS endpoint.
**Not done in this work: no real Wazuh credential has been stored anywhere.**

```bash
export OPENBAO_ADDR=https://<bao.ops.example.com> OPENBAO_ADMIN_TOKEN=<admin>
./infrastructure/openbao/aws/provision/provision.sh --set-credential wazuh-dashboard
#   Username for wazuh-dashboard: <typed>        Password (input hidden): <typed>
#   -> PASS credential wazuh-dashboard created at secret/securepam/assets/wazuh-dashboard
```
Only `win11-lab`, `kali`, `wazuh-dashboard` are accepted (argparse choices + server-side check +
exact-path policies). The password is read from a hidden prompt (or `OPENBAO_CRED_PASSWORD`), never argv.

Bind it to the registered application (admin, backend running with `SECRET_PROVIDER=openbao`):
```bash
curl -X PUT  https://<securepam>/api/v1/applications/<wazuh-app-id>/credential-ref \
     -H "Authorization: Bearer <admin>" -d '{"secret_name":"wazuh-dashboard","username":"<wazuh-user>"}'
curl -X POST https://<securepam>/api/v1/applications/<wazuh-app-id>/credential-ref/check -H "Authorization: Bearer <admin>"
```
New endpoints (`GET/PUT/DELETE /applications/{id}/credential-ref`, `POST …/check`) [TESTED, 24 tests]:
admin-only (`vault:read`/`vault:manage`); `secret_name` must be in `APPLICATION_CREDENTIAL_SECRET_NAMES`
(default `["wazuh-dashboard"]`, validated at startup, test-enforced to match both policies); client-supplied
`vault_path`/`provider`/`password` rejected (`extra="forbid"`); one credential binds to one application (409);
grants/denials audited without values; the check fails closed (`unavailable`, `access_denied`,
`secret_not_found`) and never returns or logs the secret. Isolated web sessions never check it out —
the operator signs in to Wazuh manually.

---

## 7. Keycloak package layout and Compose

Sources: `SecurePAM_keycloak_Package.docx` (the handoff guide; its text is identical to
`docs/SecurePAM_Teammate_Reproduction_Guide.docx` inside the ZIP) and `SecurePAM_keycloak_Package.zip`
(`SecurePAM_Teammate_Reproduction_Package/`, inspected and extracted only to a scratch directory; all
paths were relative, none escaped). The ZIP's `keycloak-extension/` is already in this repository (identical logic). Integrated natively
instead of copying a second package folder:

| Package file | In the repository |
|---|---|
| `keycloak-extension/` | `keycloak-extension/` (unchanged) |
| `Dockerfile.keycloak` | `infrastructure/keycloak/Dockerfile` (paths adapted; `KC_DB=postgres` at build time) |
| `docker-compose.keycloak.override.yml` | `docker-compose.keycloak.yml` (same service/volume/network names) |
| `realm-import/securepam-realm.sanitized.json` | `infrastructure/keycloak/realm-import/securepam-realm.json` (corrected, below) |
| `.env.example` | merged into root `.env.example` |

**Security finding in the supplied package:** the "sanitized" realm export still contains the source
environment's **realm key material** — RSA signing and encryption private keys, and the HMAC and AES
secrets. Anyone holding the ZIP can forge tokens for that environment. The repository's import omits
all four `KeyProvider` components (Keycloak generated fresh keys — verified). **Owner action:** rotate
the realm keys of the environment the export came from and stop circulating the ZIP.

Also added: the service-account role mapping missing from the export (without it the reader gets 403
on `/events`) — `realm-management: view-events` only.

```bash
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml --profile lab config --quiet   # [TESTED LIVE]
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml --profile lab up -d --build keycloak
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml --profile lab logs --tail 100 keycloak
```
Local secrets: root `.env` (git-ignored, 0600) holds freshly generated `KEYCLOAK_DB_PASSWORD`,
`KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`. Keycloak is published on `127.0.0.1:8080` only
(`start-dev`, HTTP): local development, never a public endpoint, separate from any AWS identity deployment.

---

## 8. Realm events and the audit-reader client [TESTED LIVE]

- Realm `securepam`: `eventsEnabled=true`, listeners `jboss-logging, securepam-otp-audit`, `LOGIN_ERROR` stored, `adminEventsEnabled=false`.
- `securepam-audit-reader`: confidential, service-account only; secret rotated after import and stored at
  `~/.securepam/keycloak-audit-reader.secret` (0600). Effective permissions (tested with its own token):
  events 200; users 403; clients 403; create user 403. `view-events` inherently also covers
  `/admin-events` (no narrower Keycloak role exists); admin-event recording is disabled in this realm.
- The persisted OTP-failure event carries no `username` detail, so with `view-events` only the imported
  row shows the Keycloak user ID (`target_id`) and "username unavailable". Granting `view-users` would
  resolve names but exposes all user records to this client; it was deliberately not granted.

---

## 9. Backend MFA event synchronization

`backend/app/services/keycloak_mfa_sync.py`, started by `app/main.py` when `KEYCLOAK_MFA_SYNC_ENABLED=true`:
token via client credentials → `GET /admin/realms/securepam/events?type=LOGIN_ERROR&dateFrom=…`
(paged) → keep exactly the listener's rule (`invalid_user_credentials` + non-empty
`selected_credential_id`; wrong passwords never match) → exact lookback cutoff → dedupe (stable
`kc-` id from the Keycloak event id, checked against the DB **and** within the run) → `MFA_FAILURE`
audit row (Keycloak's event time, severity `MEDIUM`) → SIEM sink → loop logs
`fetched / otp_failures / outside_lookback / already_imported / imported_count`.

Changes: credentials via settings (`KEYCLOAK_AUDIT_CLIENT_ID`, `KEYCLOAK_AUDIT_CLIENT_SECRET` as
`SecretStr`) — the previous `os.getenv` did not see values a host-run backend loads from `.env`;
in-run dedupe; SIEM emission (previously skipped); severity `MEDIUM` (the UI has no `WARNING`);
detail key renamed so the SIEM redactor no longer masks it; precise errors for auth failure and missing `view-events`.

Configuration (`.env.example`): `KEYCLOAK_AUDIT_CLIENT_ID=securepam-audit-reader`,
`KEYCLOAK_AUDIT_CLIENT_SECRET=<local only>`, `KEYCLOAK_MFA_SYNC_ENABLED=true`,
`KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS=60`, `KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS=1`; for a host-run backend
`KEYCLOAK_URL=http://localhost:8080`. The code default for `KEYCLOAK_MFA_SYNC_ENABLED` stays `false`
(the loop needs the secret), preserving the existing contract.

---

## 10. End-to-end acceptance results [TESTED LIVE, 2026-10-15]

| # | Check | Observed |
|---|---|---|
| 1 | Provider built and loaded | image built in Docker (Java 17/Maven); `KC-SERVICES0047 securepam-otp-audit … internal SPI eventsListener` at start |
| 2 | Invalid OTP → Keycloak log | exactly 1 new `SECUREPAM_MFA_FAILURE eventId=6e201356-… clientId=securepam-app` |
| — | Wrong password (negative control) | rejected; persisted as LOGIN_ERROR **without** `selected_credential_id`; not imported |
| 3 | Backend import | run 1: `fetched=4 otp_failures=1 imported=1` |
| 4 | Security events + dashboard | `/api/v1/audit/?action=MFA_FAILURE` shows `kc-38dab071…` (MEDIUM, FAILURE); dashboard `failed_mfa_attempts` 0 → 1 |
| 5 | Valid OTP positive control | sign-in completed and the authorization code was exchanged for tokens |
| 6 | Repeat sync | run 2: `imported=0 already_imported=1`; real background loop (temporary instance on :8001) logged the same; no duplicate ids |
| 7 | Reader permissions | see §8 |
| 8 | No secrets in output | script and loop output scanned: client secret, TOTP seed and codes absent |

The test user (`mfa-test-16ef18`) was disposable: enrolled by the script, its TOTP seed held only in
memory, deleted afterwards (its persisted events remain for audit).

To run the sync permanently in the host-run backend, add to its runtime configuration (protected, e.g.
`chmod 600 backend/.env` — currently 0644) `KEYCLOAK_URL=http://localhost:8080`,
`KEYCLOAK_AUDIT_CLIENT_SECRET=<contents of ~/.securepam/keycloak-audit-reader.secret>`,
`KEYCLOAK_MFA_SYNC_ENABLED=true`, then restart the backend. Not done here: the running backend was not modified.

---

## 11. Troubleshooting

| Symptom | Cause / check |
|---|---|
| `NET::ERR_CERT_AUTHORITY_INVALID` | Private issuer not trusted. Isolated browser: `trust_policy.py` + recreate. Never bypass. |
| `NET::ERR_CERT_COMMON_NAME_INVALID` / `IP address mismatch` | SAN lacks the registered host/IP. Reissue. |
| `NET::ERR_CERT_INVALID` with a trusted private CA | Chromium: *Not permitted by name constraints* — **every** SAN must be inside the policy constraints (e.g. drop `127.0.0.1` or add it). Debug: run Chromium with `--enable-logging=stderr --vmodule=*cert*=3` inside the container. |
| Isolated session `TLS_VALIDATION_FAILED` | `openssl s_client -connect host:443 -CAfile <ca> -verify_ip <ip>`; check the pin: `openssl s_client … \| openssl x509 -pubkey -noout \| openssl pkey -pubin -outform DER \| openssl dgst -sha256 -binary \| base64` |
| `ERR_EMPTY_RESPONSE` | Plain HTTP sent to a TLS-only port (Wazuh 443). Register `HTTPS`. |
| Proxy 502 | Upstream unreachable from the isolation container's network (SG / host down); the proxy connects to the IP pinned at start. |
| Proxy 403 / `NOT_REGISTERED_DESTINATION` | Request to a host:port other than the registration (expected for third-party calls). |
| Dashboard 503 right after restart | OpenSearch Dashboards still starting; wait for 200. |
| OpenBao 403 on first credential write | Writer policy lacks `create` (fixed). |
| OpenBao 403 on read | App token expired/revoked or path not in `securepam-app`; `--verify-only`. |
| `cannot enable audit device via API` | Declare it in `bao-config.hcl` (2.x). |
| `unknown wrapper: awskms` / `plugin directory not configured` | 2.7.1 needs the plugin + `plugin_directory`. |
| Keycloak provider not loaded | `docker logs securepam-keycloak \| grep securepam-otp-audit`; image must be `securepam-keycloak-mfa-audit:24.0`; JAR in `/opt/keycloak/providers`. |
| Login form → 400 "We are sorry…" | Cookie host mismatch: use `http://localhost:8080` (KC_HOSTNAME), not `127.0.0.1`. |
| `imported_count: 0` | Read the loop's counts: `fetched=0` → events not persisted / wrong realm / `dateFrom`; `otp_failures=0` → only password failures (by design); `outside_lookback>0` → raise `KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS`; `already_imported>0` → dedupe working. `KEYCLOAK_EVENTS_FORBIDDEN` → grant `view-events`; `KEYCLOAK_AUDIT_READER_AUTH_FAILED` → secret rotated/not loaded. |

---

## 12. Rollback and cleanup (no data loss)

- Isolated browser: delete `trust/chromium-policy.json`, `docker compose up -d --force-recreate` (Wazuh then fails closed).
- Wazuh host: restore the `/root/wazuh-dashboard-certs-backup-…` directory and restart `wazuh-dashboard` (see §2).
- Keycloak: `docker compose -f docker-compose.yml -f docker-compose.keycloak.yml --profile lab stop keycloak keycloak-postgres`.
  Never `down -v`; the `securepam_keycloak_postgres_data` volume holds the realm, users and MFA enrolments.
  To go back to the stock image, start without the overlay file (data is kept).
- Backend sync: `KEYCLOAK_MFA_SYNC_ENABLED=false`. Imported audit rows are history; do not delete them.
- AWS: `terraform destroy` only after a Raft snapshot; keep the KMS key for its full deletion window.

## 13. What was tested vs. what needs an operator

| Item | Status |
|---|---|
| Wazuh certificate reissued, trusted in the isolated browser, page + input through SecurePAM | **TESTED LIVE** |
| Gateway accept/reject matrix, SSRF/metadata/loopback blocks | **TESTED LIVE** + unit tests |
| OpenBao policies, provisioner, verifier, rotation, create/update | **TESTED** on throwaway OpenBao 2.7.1 servers |
| Terraform | `fmt` + `validate` + template render only; **no plan/apply (no AWS access)** |
| AWS deployment, KMS unseal, Let's Encrypt, Secrets Manager push, CloudWatch shipping | **OPERATOR** |
| Real Wazuh credential in OpenBao + application binding | **OPERATOR** (after AWS verification) |
| Keycloak provider, realm, reader, MFA import, dashboard, dedupe | **TESTED LIVE** (local lab) |
| Permanent sync in the running backend | **OPERATOR** (config + restart) |
| Rotate the source environment's realm keys exposed in the ZIP | **OWNER** |
