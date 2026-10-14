# Narrow credential-WRITER policy for the approved credential-management
# identity (operator runbook / provision automation ONLY — never the browser,
# never the SecurePAM backend runtime).
#
# Allows creating and updating the secret payload on EXACTLY the registered
# credential paths, and nothing else:
#   - "create" + "update" on the three data paths (win11-lab, kali,
#     wazuh-dashboard). KV v2 runs an existence check on data paths: the
#     FIRST write of a key needs "create" (HTTP 403 with "update" alone,
#     verified against OpenBao 2.7.1); later writes need "update".
#   - No read: the writer proves writes by status code, then verifies with
#     scripts/verify_openbao_token.py from the admin side.
#   - No delete/destroy/undelete on delete_/destroy_ endpoints and no
#     metadata access: versions can never be soft-deleted, destroyed, or
#     have their retention altered through this identity.
#   - No list, no sys/*, no auth/token/*: it cannot mint tokens, change
#     policies, or inspect the server.
#
# Writer tokens are short-lived (see provision/rotate), single-purpose, and
# stored only in AWS Secrets Manager + a 0600 operator file outside the repo.

path "secret/data/securepam/assets/win11-lab" {
  capabilities = ["create", "update"]
}

path "secret/data/securepam/assets/kali" {
  capabilities = ["create", "update"]
}

path "secret/data/securepam/assets/wazuh-dashboard" {
  capabilities = ["create", "update"]
}
