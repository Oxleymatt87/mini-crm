# CLAUDE.md — Oxley Tire mini-CRM

Operational guide for Claude Code sessions on this repo. **Read this first.**

> **Secrets are NOT in this file or anywhere in the repo.** They live in the
> session **environment configuration** as env vars (see "Credentials" below).
> Never commit token/secret/password values to git.

## What this is
Mini-CRM + field tools for **Oxley Tire Inc.** (commercial truck-tire wholesaler,
Southeast Texas / "SETX", Beaumont area). Pieces:
- **Web app / map** — Firebase Hosting site `inventory-setup-b3f20.web.app`
  (`public/`), incl. `map.html` (550+ pins, prospects, voice, AI chat).
- **Cloudflare Workers** (`workers/`) — QBO/Plaid/AI backends.
- **Firestore** — collections `items` (inventory), `prospects`, `map_notes`, etc.

## Branch policy — IMPORTANT
- **`master` is the canonical / deploy branch.** Firebase Hosting is deployed
  from a `master` checkout (`~/oxley-inventory` on the owner's device).
- `main` is GitHub's default and is kept **identical to `master`**. Earlier web
  sessions defaulted to `main` and diverged once — avoid that.
- **Base all new work on `master`** unless told otherwise; keep `main` in sync.

## Deploy procedures
### Firebase Hosting (the web app / map / prospects)
```sh
cd ~/oxley-inventory && git pull && npx firebase-tools deploy --only hosting
```
Needs Firebase auth: `FIREBASE_TOKEN` env var (from `npx firebase-tools login:ci`)
or an interactive `firebase login`. `firebase-tools` runs fine on Termux.

### Cloudflare Workers
`wrangler deploy` works on a normal machine, **but NOT on Termux** (`workerd`
has no Android/arm64 build — `Unsupported platform`). From Termux or a headless
container, deploy via the **REST API** with `curl` (module worker, multipart):
```sh
curl -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/<name>" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-01-15","bindings":[...]};type=application/json' \
  -F 'worker.js=@worker.js;type=application/javascript+module'
# then enable the workers.dev route once:
#   POST .../workers/scripts/<name>/subdomain  {"enabled":true}
```
Gotcha: a Worker **cannot fetch another `*.workers.dev` URL on the same account**
(Cloudflare error 1042). Use a **service binding** instead of the public URL.

## Key identifiers (non-secret)
- Cloudflare account: `e450a418975ed9b1212f52452bb1b5d5` (workers on `*.moxley.workers.dev`)
- Firebase project: `inventory-setup-b3f20` · owner UID `uSOqxJc3BigB2R6SWAaiXrb4sLj1`
- QBO realm: `9130357532009796` · app **AB8** (NOT ABQ — ABQ returns invalid_client)
- Apify Google Maps Extractor actor: `2Mdma1N6Fd0y3QEjR`
- KV namespace `QBO_TOKENS`: `9e61d4d0d02a476692cfa71c1002908b`

## Workers
- **`qbo-refresh-worker`** (`qbo-refresh-worker.moxley.workers.dev`) — QBO + Plaid
  backend. Cron every ~50 min refreshes the QBO OAuth token. Reads/writes KV
  `QBO_TOKENS` (keys: `access_token`, `expires_at`, `refresh_token`,
  `plaid_access_token`, `plaid_item_id`). **Deployed version (v17) is AHEAD of
  the repo copy** — treat `workers/qbo-refresh-worker/worker.js` as possibly stale.
  Endpoints: `/dad`, `/dashboard-summary`, `/overdue-invoices`,
  `/chase-transactions?days=`, `/bank-transactions`, `/profit-loss`,
  `/top-customers?year=`, `/expenses-detail`, `/payments-by-customer`,
  `/connect-chase`, `/new-prospect` (POST, Apify webhook → Firestore).
- **`claude-proxy`** (`claude-proxy.moxley.workers.dev`) — Anthropic Messages API
  proxy with Oxley sales-copilot prompt. Secret `ANTHROPIC_API_KEY` on the worker.
- **`oxley-mcp-server`** (`oxley-mcp-server.moxley.workers.dev`) — MCP server
  (JSON-RPC 2.0 over HTTP). `GET /status`; `POST /` for `initialize`/`tools/list`/
  `tools/call`. Proxies `qbo-refresh-worker` via a **`QBO` service binding** and
  reads `QBO_TOKENS` via a KV binding. 11 tools incl. `qbo_token_status`
  (reports token presence/length/expiry — never secret values; the endpoint is
  **public/unauthenticated**, so do not add tools that return raw secrets).
  Source: `workers/oxley-mcp-server/`.

## Prospects pipeline (SETX lead database)
- `public/prospects.json` — array of `{n:name, a:address, t:lat, g:lng,
  p?:phone, c?:category, w?:website}`. Loaded by `map.html` and rendered as pins.
- Build leads with the **Apify Google Maps Extractor** (actor above). Input:
  `searchStringsArray` of `"<category> <SETX city>"`, `maxCrawledPlacesPerSearch`
  ~12, `maxImages:0`, `maxReviews:0`. Do NOT send `countryCode` (breaks this actor).
- Merge/dedup: filter to SETX bbox (lat 29.55–31.10, lng −94.95…−93.55, excludes
  Houston), dedup by normalized name + ~35m coordinate proximity against existing
  `prospects.json` AND the hardcoded `LOCATIONS` in `map.html`, and drop
  retail/non-fleet categories (gas stations, grocery/convenience, food banks,
  restaurants, consultants). ICP = fleet operators (trucking, oilfield, construction
  & materials, logging/ag, waste, propane, fuel, mats, equipment haulers,
  industrial, food/goods distributors). Currently 830 entries.
- **Apify has a monthly usage hard limit** — if runs fail with
  `platform-feature-disabled / Monthly usage hard limit exceeded`, raise it in
  Apify Console → Settings → Billing & Usage → Limits.

## Credentials (set as env vars in the session environment — never in the repo)
Future sessions should have these provisioned in the environment config:
- `CLOUDFLARE_API_TOKEN` — Workers Scripts:Edit + Workers KV:Edit on the account
- `FIREBASE_TOKEN` — for `firebase-tools deploy` (from `firebase login:ci`)
- `APIFY_TOKEN` — for Apify actor runs
- (QBO client secret, Plaid secrets, Firebase password live in their respective
  dashboards / the worker's secrets, not here.)
If a needed credential isn't in the environment, ask the owner to add it to the
environment configuration rather than pasting it into chat or committing it.
