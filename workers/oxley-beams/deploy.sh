#!/bin/sh
# Deploy the oxley-beams worker (3D beam map; page HTML base64 in B64).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit + Workers KV:Edit.
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
NOTES_KV="${NOTES_KV:-07bde4cf73034c9dba16cd08f5170f7b}"  # OXLEY_BEAM_NOTES
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/oxley-beams" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F "metadata={\"main_module\":\"worker.js\",\"compatibility_date\":\"2024-11-01\",\"bindings\":[{\"type\":\"kv_namespace\",\"name\":\"NOTES\",\"namespace_id\":\"$NOTES_KV\"}]};type=application/json" \
  -F 'worker.js=@worker.js;type=application/javascript+module'
