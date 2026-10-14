#!/bin/sh
# Thin wrapper for the idempotent AWS provisioner.
#
#   OPENBAO_ADMIN_TOKEN=... ./provision.sh --addr https://bao.securepam.internal
#
# Secrets enter only via environment (bootstrap/admin token) or hidden
# prompts (recovery keys are never typed; credential passwords via
# OPENBAO_CRED_PASSWORD or a hidden prompt). Nothing secret is echoed,
# logged, or committed. See ../README.md for the full operator runbook.
set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$REPO_ROOT/backend"
exec "$REPO_ROOT/backend/.venv/bin/python" -m scripts.openbao_aws_provision "$@"
