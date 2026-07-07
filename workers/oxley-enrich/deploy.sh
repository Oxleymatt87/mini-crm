#!/bin/sh
# Deploy the oxley-enrich worker (batch Places enrichment of Tier-1 yards).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit + Workers KV:Edit.
# wrangler has no Termux/arm64 build, so deploy via the REST API (per CLAUDE.md).
#
# After deploy, run the enrichment (spends Places API $) with:
#   curl "https://oxley-enrich.moxley.workers.dev/run?key=<PLACES_API_KEY>"
# Read cached results:  /enriched.json   ·   photos:  /photo/<placeId>
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
ENRICH_KV="${ENRICH_KV:-c461b358ba6e491d95754fc08e6cc7c3}"  # OXLEY_ENRICH namespace
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/oxley-enrich" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F "metadata={\"main_module\":\"worker.js\",\"compatibility_date\":\"2025-01-01\",\"bindings\":[{\"type\":\"kv_namespace\",\"name\":\"ENRICH\",\"namespace_id\":\"$ENRICH_KV\"}]};type=application/json" \
  -F 'worker.js=@worker.js;type=application/javascript+module'
