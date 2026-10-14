# OpenBao on AWS (production) — SecurePAM

> Verified details, fixes and test status: `docs/SECUREPAM_WAZUH_OPENBAO_KEYCLOAK_IMPLEMENTATION.md` (§4–§6).
> Administrator identity, UI access, root escrow/retirement and **recovery when no root/admin token works**:
> `docs/SECUREPAM_PRODUCTION_READINESS_AND_IMPLEMENTATION.md` §3 (`--bootstrap-admin`, `--verify-admin`,
> `--escrow-root-arn`, `--retire-root`, `--generate-root`). Routine operations use the `securepam-admin`
> userpass identity, not root.
> Let's Encrypt needs a name under a registered domain plus a PUBLIC zone for the ACME TXT record.

Single private-node deployment with Raft persistence, end-to-end TLS, KMS
auto-unseal, and least-privilege identities. The lab dev server
(`docker compose --profile lab`, in-memory, plain HTTP, well-known root
token) is untouched by everything here and must never be used in production.

```
                                    ┌──────────── private subnets ────────────┐
                                    │                                         │
  SecurePAM backends ──TLS──▶       │  NLB :443 (TCP passthrough, internal)   │
  (SG: allowed)              │       │        │                                │
                             │       │        ▼                                │
  Admin (VPN/bastion SG ──TLS──▶     │  EC2:8200 (OpenBao, LE cert for         │
  or SSM port-forward)       │       │   bao.<zone>, Raft on encrypted EBS)   │
                                    │        │ KMS seal   │ Route53 DNS-01     │
                                    └────────┼────────────┼────────────────────┘
                                             ▼            ▼
                                      KMS CMK      private hosted zone
                                      (seal)       (A record + ACME TXT)
```

## 1. Prerequisites (operator provides — nothing is invented here)

- AWS account, region, an existing VPC with **private** subnets (2+ AZs) and
  NAT egress, and a **private** Route53 hosted zone.
- Terraform >= 1.6 with AWS credentials for the deploying principal.
- Security-group IDs of the SecurePAM backend hosts (they originate the
  `OPENBAO_ADDR` traffic) and, optionally, admin CIDRs.
- From the pinned `openbao-plugins` release page: the `awskms`
  plugin tarball SHA-256 for `awskms_plugin_sha256` (checksum-verified by
  user-data; deployment fails closed on mismatch).
- A Let's Encrypt account email (DNS-01 only — no inbound HTTP needed).
- An SSM Session Manager path to the instance (no SSH anywhere; the
  instance has no public IP and no port-22 rule).

## 2. Deploy the infrastructure

```bash
cd infrastructure/openbao/aws/terraform
terraform init
terraform apply \
  -var vpc_id=vpc-... \
  -var private_subnet_ids='["subnet-...","subnet-..."]' \
  -var route53_zone_id=Z... \
  -var acme_public_zone_id=Z... \
  -var dns_name=bao.ops.example.com \
  -var allowed_backend_security_group_ids='["sg-..."]' \
  -var 'allowed_admin_cidr_blocks=["10.0.0.0/8"]' \
  -var certbot_email=ops@example.com \
  -var awskms_plugin_sha256='<sha256 from the release page>'
```

Record the outputs (`bao_addr`, `kms_seal_key_arn`, `*_secret_arn`,
`instance_id`). user-data installs Docker, verifies + installs the pinned
`openbao-plugin-kms-awskms`, issues the LE certificate, renders
`../bao-config.hcl`, and starts `openbao:2.7.1` with IPC_LOCK on the
instance's private address only.

## 3. First-time bootstrap (idempotent — safe to re-run)

From a machine reaching `https://bao.<zone>` (admin SG or SSM forward),
with the **bootstrap token**:

- KMS seal: no unseal keys exist; on first boot OpenBao initializes with
  recovery keys and self-unseals. Save the recovery keys per your custody
  rule (split across custodians; never in git).
- Shamir fallback (if you removed the seal stanza): keep `N` shares with a
  threshold quorum; `provision` prompts for unseal only when sealed.

```bash
export OPENBAO_ADDR=https://bao.ops.example.com
export OPENBAO_ADMIN_TOKEN=...            # bootstrap credential, hidden, never committed
./infrastructure/openbao/aws/provision/provision.sh --seal awskms
```

The provisioner: skips init when already initialised (never
reinitialises) → unseals if sealed → enables KV v2 → verifies the declarative
file audit device (OpenBao 2.x refuses API-created audit devices) →
writes `securepam-app` (read-only, exact win11-lab + kali + wazuh-dashboard
paths) and `securepam-writer` (create+update only) policies → mints the 24h non-renewable
orphan app token and the 1h writer token → stores each in a 0600 file
under `~/.securepam/` and records only token **accessors** in state.
Output is `PASS`/`FAIL` lines with names and statuses only — no secret
values, ever. Then:

```bash
./infrastructure/openbao/aws/provision/provision.sh --verify-only --verify-writer \
  --allow-unstored win11-lab --allow-unstored kali --allow-unstored wazuh-dashboard   # needs OPENBAO_TOKEN
```

`--verify-only` reuses `backend/scripts/verify_openbao_token.py`: admin
lookup, exact-policy check, per-path capabilities, real reads as the app
token (field names only), denied unregistered read, denied write probe
(with cleanup), privileged-token refusal.

Push the minted tokens to Secrets Manager (values travel via `file://`,
never argv):

```bash
./infrastructure/openbao/aws/provision/provision.sh --push-secrets \
  --app-secret-arn <output app_token_secret_arn> \
  --writer-secret-arn <output writer_token_secret_arn>
```

Then **restrict the bootstrap credential** per your recovery design
(rotate the root / destroy it after recovery keys are custodied — with
KMS auto-unseal the root is only needed for disaster recovery).

## 4. Administrative access

- Day-to-day: `aws ssm start-session --target <instance_id>` (no SSH keys,
  no open ports; sessions are logged by SSM).
- `bao` CLI over TLS: `export BAO_ADDR=https://bao.<zone>` (system CAs
  verify the LE certificate; never set `BAO_SKIP_VERIFY`).
- Recovery: Shamir shares or KMS + recovery keys per §3. Test recovery on
  a cloned volume before you need it (§7).

## 5. SecurePAM application identity

The backend keeps exactly one static config change:

```bash
SECRET_PROVIDER=openbao
OPENBAO_ADDR=https://bao.<zone>          # https enforced when ENVIRONMENT=production
OPENBAO_TOKEN=<from Secrets Manager, 0600 env file>   # restricted app token ONLY
OPENBAO_CA_CERT=                          # empty: public LE chain verifies with system CAs
```

Access stays server-side (`CredentialService`); the token travels only in
the `X-Vault-Token` header, never in URLs, logs, responses, or the
frontend. The app token cannot write, list, administer, or mint tokens
(verified). Renewal loop: none needed — tokens are 24h and rotated (§6);
a restart picks up the fresh `OPENBAO_TOKEN`.

## 6. Credentials, rotation, revocation (Win11 + Kali + Wazuh)

Asset references in SecurePAM are unchanged (`securepam/assets/win11-lab`,
`securepam/assets/kali`); only admins may change them (`vault:manage`,
audited, path allowlisted server-side). The Wazuh dashboard reference is
defined as `securepam/assets/wazuh-dashboard` (policies + provisioner
allowlist) but **not stored until the AWS instance is initialized, TLS-verified,
and `--verify-only` passes**; web sessions never check credentials out — the
operator signs in manually in the isolated browser. Binding an application
row to a `vault_refs` entry needs the future application
credential-reference endpoint (`credential_refs.py` is asset-only today).

Store/update one lab credential (writer identity, hidden prompt):

```bash
export OPENBAO_ADMIN_TOKEN=...
./infrastructure/openbao/aws/provision/provision.sh \
  --set-credential kali --username <lab-user>        # password via hidden prompt
```

The same command with `--set-credential wazuh-dashboard` provisions the
Wazuh dashboard login (username + password via hidden prompt, verified by
status code, never printed) — only once §3's `--verify-only` is green on
the AWS instance.

Rotate tokens without restarting or reinitializing anything (new token is
verified before the old one is revoked by accessor):

```bash
./infrastructure/openbao/aws/provision/provision.sh --rotate app
./infrastructure/openbao/aws/provision/provision.sh --rotate writer
```

Emergency revocation: revoke by accessor
(`bao auth token revoke-accessor <accessor>` from state, or rotate), which
immediately fails closed all checkouts (`PROVIDER_ACCESS_DENIED` → 503,
audited). A revoked/expired token can never silently fall back to mock —
startup and every read fail closed.

## 7. Backup, recovery, upgrades, HA limits

- **Backup:** `bao operator raft snapshot save` on a schedule (cron on the
  host or SSM Run Command) → encrypted S3 bucket with versioning + Object
  Lock. Snapshot contains secrets: bucket policy denies everyone except
  the operator role.
- **Recovery:** new host from Terraform → restore snapshot
  (`bao operator raft snapshot restore`) → KMS unseals automatically →
  re-run `provision.sh` (idempotent) → `--verify-only`.
- **Upgrades:** pin bump in `variables.tf` → snapshot first → `terraform
  apply` → `--verify-only`. Roll back by restoring the snapshot.
- **Single-node limits:** one AZ failure takes secrets offline (backends
  fail closed, sessions cannot launch). For HA: add Raft voters (§“Future
  HA” in `bao-config.hcl`), an odd quorum (3/5), snapshots to S3, and a
  load-balanced `retry_join`. Do not run two independent single nodes and
  split writes between them.
- **Cleanup:** `terraform destroy` after snapshotting; then delete the KMS
  key **only** after its deletion window and after confirming no snapshot
  will ever be restored (a destroyed seal key makes snapshots unrecoverable).

## 8. What the instance role can (and cannot) do

Allowed: `kms:Encrypt/Decrypt/DescribeKey` on the seal key;
`route53:ChangeResourceRecordSets` on the zone (ACME TXT only by
convention); log writes to `/<project>/bao-audit`; SSM core. Denied:
reading either Secrets Manager token, minting tokens, touching KMS key
policy, touching any other infrastructure. The full statements are the
`aws_iam_role_policy.instance` document in `terraform/main.tf` — review
it with `terraform plan`.
