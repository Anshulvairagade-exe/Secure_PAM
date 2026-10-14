# Routine ADMINISTRATOR identity for SecurePAM's AWS OpenBao (GUI + CLI).
#
# Login: userpass method, user "securepam-admin" (bao login -method=userpass ...). Tokens from that
# login carry this policy plus "default" (which the web UI needs for its own lookups), live 8 h
# (max 12 h) and are not root.
#
# Can: manage SecurePAM credentials under secret/securepam/ (incl. version history and soft delete),
#      browse the UI, read (not change) policies/mounts/auth methods/audit devices, take Raft
#      snapshots for backup, mint the backend reader and credential-writer tokens ONLY through their
#      token roles (which pin the policy and TTL), look up/revoke tokens by accessor for rotation,
#      check capabilities (verifier), and change its own password.
# Cannot: write policies, enable/disable auth methods or secrets engines, change audit devices,
#      create orphan or arbitrary-policy tokens, create token roles, seal/unseal,
#      restore snapshots, or touch anything outside secret/securepam/.
# Anything in the "cannot" list is a break-glass action for the escrowed root token (see docs).
# Break-glass layer 1: this identity may START root-token generation, but completing it still needs
# the recovery-key quorum held by the custodians, so the administrator alone can never become root.

# --- SecurePAM credentials (KV v2, mount "secret") ---
path "secret/data/securepam/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/securepam/*" {
  capabilities = ["read", "list", "update", "delete"]
}
path "secret/metadata/securepam" {
  capabilities = ["list"]
}
path "secret/metadata" {
  capabilities = ["list"]
}
path "secret/delete/securepam/*" {
  capabilities = ["update"]
}
path "secret/undelete/securepam/*" {
  capabilities = ["update"]
}

# --- Read-only visibility of server configuration (UI + provisioner checks) ---
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/*" {
  capabilities = ["read"]
}
path "sys/audit" {
  capabilities = ["read", "sudo"]
}
path "auth/token/roles/*" {
  capabilities = ["read"]
}

# --- Application identities: only through their roles (policy + TTL pinned by the role) ---
path "auth/token/create/securepam-app" {
  capabilities = ["create", "update"]
}
path "auth/token/create/securepam-writer" {
  capabilities = ["create", "update"]
}
path "auth/token/lookup" {
  capabilities = ["update"]
}
path "auth/token/lookup-accessor" {
  capabilities = ["update"]
}
path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}
path "sys/capabilities" {
  capabilities = ["update"]
}

# --- Backup (snapshot SAVE only; restore is break-glass) ---
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}

# --- Own password ---
path "auth/userpass/users/securepam-admin/password" {
  capabilities = ["update"]
}

# --- Break-glass: root generation still requires the recovery-key quorum ---
path "sys/generate-root-token/attempt" {
  capabilities = ["read", "update", "delete"]
}
path "sys/generate-root-token/update" {
  capabilities = ["update"]
}
