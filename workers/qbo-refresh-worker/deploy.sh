#!/usr/bin/env bash
#
# Deploy qbo-refresh-worker via the Cloudflare REST API (multipart module upload).
#
# Why this and not `wrangler`: wrangler can't run on Termux (workerd has no
# Android/arm64 build). This script uploads the worker with plain `curl`, which
# works fine on Termux / any headless box.
#
# Secrets are PRESERVED, not wiped: we declare only the KV binding explicitly and
# use `keep_bindings: ["secret_text"]` so the existing QBO_CLIENT_ID /
# QBO_CLIENT_SECRET / PLAID_CLIENT_ID / PLAID_SECRET secrets carry over untouched.
# Cron triggers (*/50 * * * *) are managed separately and are not affected by a
# script upload.
#
# Requires: CLOUDFLARE_API_TOKEN env var (Workers Scripts:Edit on the account).
#
# Usage:  cd workers/qbo-refresh-worker && ./deploy.sh
set -euo pipefail

ACCOUNT="e450a418975ed9b1212f52452bb1b5d5"
SCRIPT="qbo-refresh-worker"
KV_NAMESPACE_ID="9e61d4d0d02a476692cfa71c1002908b"   # QBO_TOKENS
COMPAT_DATE="2024-11-01"

cd "$(dirname "$0")"

if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "ERROR: CLOUDFLARE_API_TOKEN is not set." >&2
  exit 1
fi
if [ ! -f worker.js ]; then
  echo "ERROR: worker.js not found in $(pwd)" >&2
  exit 1
fi

METADATA=$(cat <<JSON
{
  "main_module": "worker.js",
  "compatibility_date": "${COMPAT_DATE}",
  "bindings": [
    { "type": "kv_namespace", "name": "QBO_TOKENS", "namespace_id": "${KV_NAMESPACE_ID}" }
  ],
  "keep_bindings": ["secret_text"]
}
JSON
)

echo "Uploading ${SCRIPT} to account ${ACCOUNT}..."
RESP=$(curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/${SCRIPT}" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -F "metadata=${METADATA};type=application/json" \
  -F "worker.js=@worker.js;type=application/javascript+module")

echo "$RESP"
if echo "$RESP" | grep -q '"success":true'; then
  echo
  echo "✅ Deployed. Verify the modernized Reports backend with:"
  echo "   curl -s 'https://qbo-refresh-worker.moxley.workers.dev/profit-loss?start_date=2026-01-01&end_date=2026-06-23' -D - -o /dev/null | grep -i x-qbo-modern-response"
  echo "   (X-QBO-Modern-Response: true means the modernized backend is live; false means still on legacy — both are fine pre-cutover.)"
else
  echo "❌ Deploy did not report success — check the response above." >&2
  exit 1
fi
