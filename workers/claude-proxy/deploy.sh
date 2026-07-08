#!/bin/sh
# Deploy claude-proxy (Anthropic Messages API proxy with Oxley sales copilot prompt).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit.
#
# Secret ANTHROPIC_API_KEY is already provisioned on the worker via the
# Cloudflare dashboard and persists across deploys.
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"

echo "==> uploading claude-proxy script..."
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/claude-proxy" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-01-15","bindings":[]};type=application/json' \
  -F 'worker.js=@src/worker.js;type=application/javascript+module' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL: '+str(d.get('errors')))"
