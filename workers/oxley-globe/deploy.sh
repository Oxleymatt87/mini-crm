#!/bin/sh
# Deploy the oxley-globe worker (module worker, KML embedded inline).
# Needs CLOUDFLARE_API_TOKEN with Workers Scripts:Edit on the account.
# wrangler has no Termux/arm64 build, so deploy via the REST API (per CLAUDE.md).
CF_ACCOUNT="${CF_ACCOUNT:-e450a418975ed9b1212f52452bb1b5d5}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
cd "$(dirname "$0")"
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/oxley-globe" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-01-01","bindings":[]};type=application/json' \
  -F 'worker.js=@worker.js;type=application/javascript+module'
