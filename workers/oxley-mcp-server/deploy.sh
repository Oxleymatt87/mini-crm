#!/bin/sh
# Deploy oxley-mcp-server (MCP server proxying qbo-refresh-worker finance tools).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit + Workers KV:Edit.
#
# Bindings:
#   QBO          — service binding to qbo-refresh-worker (avoids CF error 1042)
#   QBO_TOKENS   — KV namespace (read-only token metadata for qbo_token_status)
#   UPSTREAM_BASE — plain-text var (fallback URL, not used on same-account calls)
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
QBO_TOKENS_KV="${QBO_TOKENS_KV:-9e61d4d0d02a476692cfa71c1002908b}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"

echo "==> uploading oxley-mcp-server script..."
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/oxley-mcp-server" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F "metadata={\"main_module\":\"worker.js\",\"compatibility_date\":\"2025-01-15\",\"bindings\":[{\"type\":\"service\",\"name\":\"QBO\",\"service\":\"qbo-refresh-worker\"},{\"type\":\"kv_namespace\",\"name\":\"QBO_TOKENS\",\"namespace_id\":\"$QBO_TOKENS_KV\"},{\"type\":\"plain_text\",\"name\":\"UPSTREAM_BASE\",\"text\":\"https://qbo-refresh-worker.moxley.workers.dev\"}]};type=application/json" \
  -F 'worker.js=@worker.js;type=application/javascript+module' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL: '+str(d.get('errors')))"
