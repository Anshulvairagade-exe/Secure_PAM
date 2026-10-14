# OpenBao server configuration for the SecurePAM AWS deployment (single node).
#
# Rendered ONCE on the EC2 host by user-data.sh via envsubst; the template
# itself carries no secrets, addresses, or key IDs — everything deployment-
# specific arrives as environment variables listed in terraform/variables.tf.
#
# What this enforces (and the lab dev server does not):
#   - Integrated Raft storage on an EBS volume (persistent; survives restarts).
#   - TLS on the API listener (min TLS 1.2). No plaintext listener exists.
#   - Binds the API to the instance's PRIVATE address only; the security
#     group admits 8200 solely from the NLB / SecurePAM backends and a
#     dedicated admin bastion/SSM path (see terraform/).
#   - Web UI enabled (ui = true) but reachable only on the private listener (SSM port-forward or
#     the internal NLB from admin networks); never published.
#   - Seal: AWS KMS auto-unseal via the awskms KMS plugin (OpenBao 2.7.1
#     has no built-in awskms seal; the plugin stanza below registers it). The plugin authenticates with the instance IAM role — no static
#     AWS credentials appear here. For the Shamir fallback, delete the
#     plugin + seal stanzas and follow aws/README.md "Manual Shamir seal".
#
# Template variables (all required at render time):
#   ${NODE_PRIVATE_IP}   private IPv4 of this EC2 instance
#   ${AWS_REGION}        region hosting the KMS seal key
#   ${KMS_KEY_ID}        KMS key ID or ARN used as the seal
#   ${KMS_ENDPOINT}      optional VPC-endpoint URL for KMS (empty string = default endpoint)
#   ${PLUGIN_DIR}        host dir containing the pinned openbao-plugin-kms-awskms binary

storage "raft" {
  path    = "/openbao/raft"
  node_id = "securepam-bao-1"
}

listener "tcp" {
  address            = "${NODE_PRIVATE_IP}:8200"
  cluster_address    = "${NODE_PRIVATE_IP}:8201"
  tls_cert_file      = "/openbao/tls/tls.crt"
  tls_key_file       = "/openbao/tls/tls.key"
  tls_min_version    = "tls12"
  tls_cipher_suites  = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
}

api_addr     = "https://${NODE_PRIVATE_IP}:8200"
cluster_addr = "https://${NODE_PRIVATE_IP}:8201"
# Web UI: served on the same TLS listener as the API, i.e. ONLY on the private address behind the
# internal NLB / an SSM port-forward (never public). Login uses the securepam-admin userpass identity.
ui           = true

# No mlock setting: OpenBao 2.x removed mlock support and rejects
# `disable_mlock` as an unknown field (verified against 2.7.1). Keep swap
# disabled on the host instead (AL2023 EC2 has no swap by default).

# --- Auto-unseal via AWS KMS (external plugin; verified on 2.7.1) ---
# 2.7.1 has no built-in awskms seal ("unknown wrapper: awskms"). The plugin
# stanza needs plugin_directory and a command NAME relative to it (an
# absolute command path is rejected). user-data.sh checksum-verifies the
# binary before it is placed there.
plugin_directory = "${PLUGIN_DIR}"

plugin "kms" "awskms" {
  command = "openbao-plugin-kms-awskms"
}

seal "awskms" {
  region     = "${AWS_REGION}"
  kms_key_id = "${KMS_KEY_ID}"
  endpoint   = "${KMS_ENDPOINT}"
}

# --- Audit: declarative (OpenBao 2.x refuses API-created audit devices) ---
# Shipped to CloudWatch by the agent configured in user-data.sh. Secret
# values and tokens are HMAC'd in the log, never written in plaintext.
audit "file" "file" {
  description = "SecurePAM OpenBao file audit"
  options {
    file_path = "/openbao/audit/audit.log"
  }
}

# --- Future HA: uncomment on nodes 2..n and add matching retry_join here ---
# retry_join {
#   leader_api_addr = "https://<node-1-private-ip>:8200"
# }
