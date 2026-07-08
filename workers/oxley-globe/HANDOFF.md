# oxley-globe — Session Handoff

**What this is:** `oxley-globe` is now the **single all-in-one field app** for Oxley Tire —
a Cesium 3D globe of every SE-Texas fleet, built for selling commercial truck tires in the
field on a phone. Live at **https://oxley-globe.moxley.workers.dev** (installable as a PWA).

`oxley-xr` (VR headset build) is a **different session's** job — do NOT touch it.
Another session once redeployed `oxley-globe` and clobbered this build; if you see the app
lose features, check the deploy log and re-deploy from `workers/oxley-globe/worker.js`.

---

## Current state / open PR
- Branch: `claude/oxley-globe-labels-routing-a4bqax` · **PR #57** (draft, open) — merge when ready.
- PR #56 already merged (labels/routing/enrich groundwork).
- The **live deploy is ahead of nothing** — `workers/oxley-globe/worker.js` in the repo IS
  what's deployed (keep it that way: commit every change you deploy).

## Architecture
- **oxley-globe** (this worker): one self-contained module. Serves the HTML page (`const PAGE`)
  plus routes `/manifest.json`, `/icon.svg`. Pin data is **base64-embedded** in the page as
  `var DATA_B64="..."` (JSON array of ~3,206 carriers). Cesium 1.142 from jsDelivr; Google
  Photorealistic 3D Tiles.
- **oxley-enrich** (`oxley-enrich.moxley.workers.dev`): Google Places enrichment. Serves
  `/enriched.json` (cached photo/rating/hours/phone/website by name) and `/photo/<placeId>`.
  KV binding `ENRICH` = namespace `c461b358ba6e491d95754fc08e6cc7c3` (OXLEY_ENRICH). The globe
  fetches `/enriched.json` live and shows photos in the card. `/run?key=<PLACES_KEY>` enriches
  its embedded list in batches (skips cached; Cloudflare 50-subrequest cap → `&limit=12`).
- **oxley-beams** (`oxley-beams.moxley.workers.dev`): the globe calls its `/notes` (GET) and
  `/note` (POST) **cross-origin** to sync Lead/Visited/Sold/Dead + notes. KV binding `NOTES` =
  `07bde4cf73034c9dba16cd08f5170f7b` (OXLEY_BEAM_NOTES). **Do not delete oxley-beams** or notes
  sync breaks (or move the endpoint into oxley-globe).
- **External (client-side, free):** OpenStreetMap **Overpass API** for street-name labels when
  zoomed in; Google **Routes API** (in-app routing), **Maps Embed API** (in-app Street View).

## Data pipeline (how the pins were built)
1. Base pin set (3,205) came from a prior session's "SETX Fleets" build (FMCSA carriers).
2. Joined 100% by **USDOT#** to the master workbook **`OxleyFleetIntel_SETX.xlsx`** (owner
   uploaded it; keep a copy). Baked into each pin: `ind` (industry vertical), `em` (FMCSA
   email, 2,812), `ask` (officer/owner), `pu`/`dr`/`mi` (power units/drivers/annual miles),
   `tb` (tire-burn), `dba` (992 trade names), `web` (554 sites derived from company email
   domains), `tier` (duty: General/Heavy/Severe).
3. **Reclassification:** 271 of the "Other/Unclassified" carriers re-tagged to real industries
   by business-name keywords (oilfield/construction/waste/towing/logging/trucking…).
4. **Residential flag** `res:1` on 206 home-based owner-ops (1 unit, personal name, low miles).
5. **Yard photos:** 573 real yards (power units ≥ 3) run through Places → 260 have photos.
6. Pin record fields: `n`(legal name) `dba` `ind` `tier` `pu` `dr` `mi` `tb` `em` `ph` `ask`
   `web` `city` `zip` `county` `dot` `lat` `lon` `col` `res` `src`.

## Features in the app
Industry-emoji markers colored+sized by power-unit band · zoom-in name/labels · **town labels**
(27 SETX towns) · **street names** (OSM/Overpass, when zoomed in) · big tappable **ME** GPS
marker → closest-first **📋 List** (Route/Call/Card per row) · tap pin → **fly in** + card ·
card shows trade name (legal as subtitle), industry, fleet stats, tire-burn, owner, phone,
✉ email + Email button, 🌐 Site, photo, distance · **🧭 Route on globe** (Routes API) ·
**🛣 Street** → tap ground → in-app Street View (Maps Embed API) · **🔥 Priority** (Heavy+Severe
tiers) · **🚛 Heavy** (non-destructive highlight; dims light/unknown, never removes; heavy =
heavy vertical OR name-keyword OR miles/truck ≥ 50k; residences never heavy) · search matches
name **and DBA** (plural-tolerant, ranked) → flies to best match, list is opt-in · editable
Lead/Visited/Sold/Dead + notes (KV via oxley-beams) · installable PWA.

## How to edit the pin data
`worker.js` = handler + `const PAGE = String.raw`…``. Pin data is `var DATA_B64="<base64 JSON>"`
inside PAGE. To edit: in Python, regex-extract DATA_B64, `base64.b64decode` → `json.loads`,
mutate, `json.dumps(separators=(',',':'))` → b64encode → splice back. Never introduce a raw
backtick or `${` into the PAGE content (it's a String.raw template). Validate with
`node --check workers/oxley-globe/worker.js` before deploy.

## Deploy (Cloudflare REST API — wrangler has no Termux/arm64 build)
```sh
CF_ACCOUNT=e450a418975ed9b1212f52452bb1b5d5
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/oxley-globe" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-01-01","bindings":[]};type=application/json' \
  -F 'worker.js=@workers/oxley-globe/worker.js;type=application/javascript+module'
```
`oxley-enrich` deploy adds `"bindings":[{"type":"kv_namespace","name":"ENRICH","namespace_id":"c461b358ba6e491d95754fc08e6cc7c3"}]`;
`oxley-beams` adds the NOTES binding `07bde4cf73034c9dba16cd08f5170f7b`. See each worker's `deploy.sh`.

## Identifiers (non-secret)
- Cloudflare account: `e450a418975ed9b1212f52452bb1b5d5` (workers on `*.moxley.workers.dev`).
- KV: OXLEY_ENRICH `c461b358ba6e491d95754fc08e6cc7c3` · OXLEY_BEAM_NOTES `07bde4cf73034c9dba16cd08f5170f7b`.
- Google Maps key (browser, referrer-restricted, already in `worker.js`): `AIzaSyDsv6pVM0beDl0xaqNWmVkyBiUuzxRDr5c`.
  Used for 3D Tiles + Routes + Maps Embed (Street View). Same key powers oxley-enrich's Places calls (server-side).

## CREDENTIALS — read this
Secrets do **not** live in the repo (policy + safety). Provision them as **environment
variables in the session/environment config** so future sessions have them:
- **`CLOUDFLARE_API_TOKEN`** — required to deploy any worker. Needs Workers Scripts:Edit +
  Workers KV:Edit on the account. This session did NOT have it in env; the owner uploaded it as
  a file mid-session. **Ask the owner to add it to the environment config** (or upload again).
- The **Google Maps key** above is a browser key already embedded in the page (public by
  design, referrer-locked) — fine to keep in code. For it to fully work you must enable on it,
  in Google Cloud console (project `inventory-setup-b3f20`), the APIs: **Map Tiles, Routes,
  Maps Embed** (Routes + Embed were the blockers for in-app routing / street view).
- Do NOT paste the Cloudflare token or any private key into a committed file.

## Known walls / honest limits
- **FMCSA has no truck weight-class field** — medium vs. light is an *estimate* (vertical +
  name keywords + miles/truck). Never filter out by low miles (local heavy fleets run low miles).
- ~1,000 "Other/Unclassified" carriers can't be read from the name (generic Enterprises/Group).
- ~180 big personal-name yards (e.g. "JOSE BENITEZ", 10 units) have **no public business name**
  anywhere — not FMCSA, not Google. A Places-by-address pass (~$7) resolved only 1/165; abandoned.
  Fix path: an in-app **✏️ Rename** tool (save to KV) so the owner names them in the field.
- **ZoomInfo** connector is added but exposes **no tools** ("No tools provided for this MCP
  server") — titled decision-maker contacts (Fleet Manager/Maintenance/Ops) are NOT available
  via MCP. Would require a manual ZoomInfo web export (paid) merged like the workbook.
- Google's POI labels and native business card do not render on 3D tiles; spoken turn-by-turn
  nav isn't possible in a browser.

## Suggested next steps
1. Merge PR #57.
2. Owner: confirm Routes + Maps Embed APIs enabled on the Google key (for routing + Street View).
3. Build the **✏️ Rename** card tool for the no-name big yards (saves to OXLEY_BEAM_NOTES KV).
4. Optional: Google **Places category sweep** to add genuinely non-FMCSA truck operators
   (welding/oilfield/construction/waste/etc.) — **exclude restaurants, farms, ranches, gas
   stations, and retail** per owner. ~$10, ~800–1,500 pins, magenta "non-FMCSA" flag.
5. Optional: refine the `HEAVY_KW` / reclassification rules as the owner spots misreads.
