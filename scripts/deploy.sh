#!/usr/bin/env bash
set -euo pipefail

VM_IP="134.199.198.192"
VM_USER="root"

# Get the repo root (works from any subdirectory)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== Deploying from: $REPO_ROOT =="

echo "== Sync backend app/ =="
rsync -avz --delete "${REPO_ROOT}/app/" ${VM_USER}@${VM_IP}:/opt/sbm-api/app/

echo "== Sync site/ (static files) =="
rsync -avz --delete "${REPO_ROOT}/site/" ${VM_USER}@${VM_IP}:/opt/sbm-api/site/

echo "== Sync keys/ (if exists) =="
if [ -d "${REPO_ROOT}/keys" ]; then
    rsync -avz "${REPO_ROOT}/keys/" ${VM_USER}@${VM_IP}:/opt/sbm-api/keys/
fi

echo "== Install deps + restart API =="
ssh ${VM_USER}@${VM_IP} '
  set -e
  cd /opt/sbm-api
  /opt/sbm-api/.venv/bin/pip install -q httpx python-multipart cryptography slowapi coincurve
  systemctl restart sbm-api
'

echo "== Done. Smoke tests =="
curl -sS https://api.signedbyme.com/healthz && echo " ✓ API healthy"
curl -sS https://api.signedbyme.com/v1/enterprise/info && echo " ✓ Enterprise endpoint"
