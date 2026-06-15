#!/usr/bin/env bash
# Deploy the /payments-by-customer endpoint to the live qbo-refresh-worker.
#
# It fetches the CURRENT deployed worker source, patches in only the new route +
# function (everything else stays identical), then re-uploads via the Cloudflare
# multipart Workers Script API. Existing secrets are preserved via keep_bindings;
# the QBO_TOKENS KV binding is re-declared so it is retained.
#
# Requirements: bash, curl, node (Termux: `pkg install nodejs`).
# Usage:
#   export CF_API_TOKEN="<your Cloudflare API token>"
#   ./deploy_payments_endpoint.sh
set -euo pipefail

ACCOUNT_ID="e450a418975ed9b1212f52452bb1b5d5"
SCRIPT_NAME="qbo-refresh-worker"
KV_NAMESPACE_ID="9e61d4d0d02a476692cfa71c1002908b"   # QBO_TOKENS
COMPAT_DATE="2024-11-01"

: "${CF_API_TOKEN:?Set CF_API_TOKEN to your Cloudflare API token first}"

HERE="$(cd "$(dirname "$0")" && pwd)"
API="https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "→ Fetching current deployed worker source..."
curl -fsSL "${API}/content" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -o "${TMP}/current.js"

echo "→ Patching in /payments-by-customer..."
node "${HERE}/patch_payments_endpoint.js" "${TMP}/current.js" "${TMP}/worker.js"

echo "→ Uploading patched worker..."
META='{"main_module":"worker.js","compatibility_date":"'"${COMPAT_DATE}"'","keep_bindings":["secret_text","secret_key"],"bindings":[{"type":"kv_namespace","name":"QBO_TOKENS","namespace_id":"'"${KV_NAMESPACE_ID}"'"}]}'

curl -fsS -X PUT "${API}" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -F "metadata=${META};type=application/json" \
  -F "worker.js=@${TMP}/worker.js;type=application/javascript+module" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);if(j.success){console.log("✅ Deployed");}else{console.log("❌ Failed");console.log(JSON.stringify(j.errors||j,null,2));process.exit(1);}}catch(e){console.log(s);}})'

echo ""
echo "Test it:"
echo "  curl -s \"https://${SCRIPT_NAME}.moxley.workers.dev/payments-by-customer\" | head -c 2000"
echo "  # or a custom window:"
echo "  curl -s \"https://${SCRIPT_NAME}.moxley.workers.dev/payments-by-customer?start_date=2026-01-01&end_date=2026-06-14\""
