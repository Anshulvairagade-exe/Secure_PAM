#!/bin/bash
# Keycloak node bootstrap (Terraform templatefile; a doubled dollar sign before a brace is shell).
# Secrets are fetched from Secrets Manager into a root-only env file; never logged, never in user data.
set -euo pipefail

dnf install -y docker awscli jq
systemctl enable --now docker
install -d -m 700 /opt/keycloak

cat > /usr/local/bin/kc-render-env.sh <<'SCRIPT'
#!/bin/bash
# Re-render /opt/keycloak/keycloak.env from Secrets Manager; restart Keycloak when a secret changed
# (the RDS-managed master password rotates automatically).
set -euo pipefail
umask 077
REGION="__REGION__"
db=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "__DB_SECRET__" --query SecretString --output text)
admin=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "__ADMIN_SECRET__" --query SecretString --output text)
tmp=$(mktemp /opt/keycloak/env.XXXXXX)
{
  echo "KC_DB_URL=jdbc:postgresql://__DB_HOST__:5432/keycloak?sslmode=require"
  echo "KC_DB_USERNAME=$(jq -r .username <<<"$db")"
  echo "KC_DB_PASSWORD=$(jq -r .password <<<"$db")"
  echo "KEYCLOAK_ADMIN=$(jq -r .username <<<"$admin")"
  echo "KEYCLOAK_ADMIN_PASSWORD=$(jq -r .password <<<"$admin")"
  echo "KC_HOSTNAME=__HOSTNAME__"
  [ -n "__ADMIN_HOSTNAME__" ] && echo "KC_HOSTNAME_ADMIN=__ADMIN_HOSTNAME__"
  echo "KC_HOSTNAME_STRICT=true"
  echo "KC_HOSTNAME_STRICT_HTTPS=true"
  echo "KC_HTTP_ENABLED=true"
  echo "KC_PROXY_HEADERS=xforwarded"
  echo "KC_LOG=console"
} > "$tmp"
unset db admin
if ! cmp -s "$tmp" /opt/keycloak/keycloak.env 2>/dev/null; then
  mv "$tmp" /opt/keycloak/keycloak.env
  docker restart keycloak >/dev/null 2>&1 || true
else
  rm -f "$tmp"
fi
SCRIPT
sed -i -e "s|__REGION__|${aws_region}|" -e "s|__DB_SECRET__|${db_secret_arn}|" -e "s|__ADMIN_SECRET__|${admin_secret_arn}|" \
  -e "s|__DB_HOST__|${db_host}|" -e "s|__HOSTNAME__|${hostname}|" -e "s|__ADMIN_HOSTNAME__|${admin_hostname}|" \
  /usr/local/bin/kc-render-env.sh
chmod 700 /usr/local/bin/kc-render-env.sh
/usr/local/bin/kc-render-env.sh

aws ecr get-login-password --region "${aws_region}" | docker login --username AWS --password-stdin "${registry}"
docker rm -f keycloak 2>/dev/null || true
docker run -d --name keycloak --restart unless-stopped \
  -p 8080:8080 --env-file /opt/keycloak/keycloak.env \
  --log-driver awslogs --log-opt awslogs-region="${aws_region}" --log-opt awslogs-group="${log_group}" \
  "${image}"

cat > /etc/systemd/system/kc-render-env.service <<'UNIT'
[Unit]
Description=Refresh Keycloak secrets from Secrets Manager
[Service]
Type=oneshot
ExecStart=/usr/local/bin/kc-render-env.sh
UNIT
cat > /etc/systemd/system/kc-render-env.timer <<'UNIT'
[Unit]
Description=Hourly Keycloak secret refresh
[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now kc-render-env.timer
