# Least-privilege policy for the SecurePAM application identity (KV v2, mount "secret").
# Read only. No list, metadata, write, delete or sys/admin capabilities: the backend only ever does
# GET /v1/secret/data/<path> for the credential references registered on assets.
#
# One entry per registered credential reference (assets -> vault_refs.vault_path):
#   Windows 11 Lab (RDP)  securepam/assets/win11-lab
#   Kali Lab SSH          securepam/assets/kali
# Registering another asset's credential means adding its path here, then:
#   bao policy write securepam-read infrastructure/openbao/policies/securepam-read.hcl

path "secret/data/securepam/assets/win11-lab" {
  capabilities = ["read"]
}

path "secret/data/securepam/assets/kali" {
  capabilities = ["read"]
}
