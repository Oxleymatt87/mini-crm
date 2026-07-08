#!/bin/sh
# Deploy qbo-refresh-worker (QBO OAuth + Plaid/Chase + Firestore CRM).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit + Workers KV:Edit.
#
# Secrets (QBO_CLIENT_ID, QBO_CLIENT_SECRET, SHEETS_API_KEY) are already
# provisioned on the worker via the Cloudflare dashboard and persist across
# deploys — do NOT re-upload them here.
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
QBO_TOKENS_KV="${QBO_TOKENS_KV:-9e61d4d0d02a476692cfa71c1002908b}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"

echo "==> uploading qbo-refresh-worker script..."
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/qbo-refresh-worker" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F "metadata={\"main_module\":\"worker.js\",\"compatibility_date\":\"2024-11-01\",\"bindings\":[{\"type\":\"kv_namespace\",\"name\":\"QBO_TOKENS\",\"namespace_id\":\"$QBO_TOKENS_KV\"}]};type=application/json" \
  -F 'worker.js=@worker.js;type=application/javascript+module' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL: '+str(d.get('errors')))"

echo "==> setting cron schedule (0 * * * * — hourly QBO token refresh)..."
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/qbo-refresh-worker/schedules" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"cron":"0 * * * *"}]' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('cron OK' if d.get('success') else 'cron FAIL: '+str(d.get('errors')))"
