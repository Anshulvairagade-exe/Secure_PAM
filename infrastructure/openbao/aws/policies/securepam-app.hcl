# Least-privilege policy for the SecurePAM application identity (production).
# KV v2, mount "secret". Same shape as infrastructure/openbao/policies/securepam-read.hcl,
# plus the Wazuh dashboard path (lab parity is a conscious exception: the Wazuh
# credential lives in AWS OpenBao only, and web sessions never check it out —
# the operator signs in manually in the isolated browser):
# read-only on EXACTLY the registered credential paths — no wildcards, no
# list, no create/update/delete/patch, no metadata, no sys. The backend only
# ever issues GET /v1/secret/data/<path> for asset credential references.
#
# Registered references (vault_refs.vault_path; application binding for the
# Wazuh row lands with the future application credential-reference endpoint):
#   Windows 11 Lab (RDP)  securepam/assets/win11-lab
#   Kali Lab SSH          securepam/assets/kali
#   Wazuh dashboard       securepam/assets/wazuh-dashboard   (not stored until AWS OpenBao is ready)
# Registering another credential means adding its exact path here,
# re-running provision, and re-verifying with scripts/verify_openbao_token.py.

path "secret/data/securepam/assets/win11-lab" {
  capabilities = ["read"]
}

path "secret/data/securepam/assets/kali" {
  capabilities = ["read"]
}

path "secret/data/securepam/assets/wazuh-dashboard" {
  capabilities = ["read"]
}
