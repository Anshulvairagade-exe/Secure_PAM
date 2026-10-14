#!/bin/bash
# EC2 user-data for the SecurePAM OpenBao node. Runs ONCE at first boot as root.
# Idempotent where it matters (block device, plugin checksum, cert issuance).
# Carries NO secrets: KMS auth comes from the instance role; tokens are minted
# later by provision/provision.sh and stored in Secrets Manager.
#
# This file is a Terraform templatefile(): a doubled dollar sign before a
# brace is a literal shell expansion; a single one is a Terraform variable.
# Template variables:
# aws_region, openbao_version, awskms_plugin_version, awskms_plugin_sha256,
# kms_key_id, dns_name, certbot_email, project, data_volume_id, bao_config_b64.
set -euo pipefail

IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
PRIVATE_IP=$(curl -s --fail -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
export NODE_PRIVATE_IP="$PRIVATE_IP" AWS_REGION="${aws_region}" KMS_KEY_ID="${kms_key_id}"
export KMS_ENDPOINT="" PLUGIN_DIR="/openbao/plugins"
BAO_UID=100 BAO_GID=1000   # the openbao user inside openbao/openbao images (su-exec drops to it)

dnf install -y docker gettext awscli certbot python3-certbot-dns-route53 amazon-cloudwatch-agent
systemctl enable --now docker

# --- Persistent data volume ---
# On Nitro instances an EBS volume attached as /dev/sdf appears as an NVMe
# device; the stable name embeds the volume ID. The attachment is a separate
# Terraform resource, so wait for it rather than racing first boot.
VOL_ID_NODASH=$(echo "${data_volume_id}" | tr -d '-')
DEV=""
for i in $(seq 1 120); do
  for cand in "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$${VOL_ID_NODASH}" /dev/sdf /dev/xvdf; do
    if [ -b "$cand" ]; then DEV=$(readlink -f "$cand"); break 2; fi
  done
  sleep 5
done
[ -n "$DEV" ] || { echo "data volume ${data_volume_id} never attached" >&2; exit 1; }
if ! blkid "$DEV" >/dev/null 2>&1; then
  mkfs -t ext4 -L bao-data "$DEV"
fi
mkdir -p /openbao
grep -q " /openbao " /etc/fstab || echo "LABEL=bao-data /openbao ext4 defaults,nofail 0 2" >> /etc/fstab
mount -a
mkdir -p /openbao/raft /openbao/tls /openbao/plugins /openbao/config /openbao/audit
# The server runs as uid 100 inside the container: it must own its data,
# config and audit directories (root-owned 0700 dirs make it fail to start).
chown -R "$BAO_UID:$BAO_GID" /openbao/raft /openbao/tls /openbao/config /openbao/audit
chmod 700 /openbao/raft /openbao/tls /openbao/audit

# --- KMS auto-unseal plugin: pinned release, checksum-verified (fails closed) ---
PLUGIN_VER="${awskms_plugin_version}"
PLUGIN_SHA="${awskms_plugin_sha256}"
if [ ! -x /openbao/plugins/openbao-plugin-kms-awskms ]; then
  cd /tmp
  curl -sSL --fail -o awskms.tar.gz \
    "https://github.com/openbao/openbao-plugins/releases/download/v$${PLUGIN_VER}/openbao-plugins_$${PLUGIN_VER}_linux_amd64.tar.gz"
  echo "$${PLUGIN_SHA}  awskms.tar.gz" | sha256sum -c -
  tar -xzf awskms.tar.gz -C /openbao/plugins openbao-plugin-kms-awskms
  chmod 755 /openbao/plugins/openbao-plugin-kms-awskms
  rm -f awskms.tar.gz
fi

# --- TLS via Let's Encrypt DNS-01 (no inbound connection needed) ---
# The deploy hook copies the FULL CHAIN (leaf + intermediate) and key into
# /openbao/tls on first issuance and on every renewal, then restarts OpenBao.
# Serving the leaf alone breaks clients ("unable to get local issuer").
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/securepam-openbao.sh <<HOOK
#!/bin/sh
set -e
install -o $BAO_UID -g $BAO_GID -m 0644 "\$RENEWED_LINEAGE/fullchain.pem" /openbao/tls/tls.crt
install -o $BAO_UID -g $BAO_GID -m 0600 "\$RENEWED_LINEAGE/privkey.pem" /openbao/tls/tls.key
docker restart securepam-openbao >/dev/null 2>&1 || true
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/securepam-openbao.sh
if [ ! -f /openbao/tls/tls.crt ]; then
  certbot certonly --non-interactive --agree-tos -m "${certbot_email}" \
    --dns-route53 -d "${dns_name}" \
    --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/securepam-openbao.sh
fi
systemctl enable --now certbot-renew.timer

# --- Render server config (template carries no secrets) ---
echo "${bao_config_b64}" | base64 -d > /tmp/bao-config.hcl
envsubst '$${NODE_PRIVATE_IP} $${AWS_REGION} $${KMS_KEY_ID} $${KMS_ENDPOINT} $${PLUGIN_DIR}' \
  < /tmp/bao-config.hcl > /openbao/config/bao.hcl
shred -u /tmp/bao-config.hcl
chown "$BAO_UID:$BAO_GID" /openbao/config/bao.hcl
chmod 600 /openbao/config/bao.hcl

# --- CloudWatch agent: ship the declarative file audit device ---
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOF
{"logs": {"logs_collected": {"files": {"collect_list": [
  {"file_path": "/openbao/audit/audit.log", "log_group_name": "/${project}/bao-audit",
   "log_stream_name": "{instance_id}", "retention_in_days": 365}
]}}}}
EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config \
  -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json -s

# --- Run OpenBao (pinned image) ---
# Host networking: the listener binds the instance's PRIVATE address, which
# does not exist inside a bridged container. `server` alone: the image
# entrypoint already adds -config=/openbao/config (passing the file again
# would load it twice).
docker rm -f securepam-openbao 2>/dev/null || true
docker run -d --name securepam-openbao --restart unless-stopped \
  --network host \
  -v /openbao/config:/openbao/config \
  -v /openbao/raft:/openbao/raft \
  -v /openbao/tls:/openbao/tls:ro \
  -v /openbao/plugins:/openbao/plugins:ro \
  -v /openbao/audit:/openbao/audit \
  "openbao/openbao:${openbao_version}" server
