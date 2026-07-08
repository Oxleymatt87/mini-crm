# Oxley Fleet Intelligence — TX + LA scraper

Config-driven, single-file fleet-intelligence pipeline: `intel/scrape_fleets.py`.
Builds a private-fleet target list for Oxley Tire across Texas + Louisiana from
**free FMCSA data**, scores each carrier for "runs its own shop" (a tire-buying
signal), then — only when explicitly told to — spends Apify credits to deep-harvest
emails, website language, and mechanic/tire-tech job postings.

## The contract (read this)

- **Default run spends nothing.** It executes only the free layers (FMCSA pull,
  screens, scoring, verticals, self-service score, residential heuristic), prints
  counts, prints the Apify cost estimate, and stops.
- The **paid Apify harvest never runs** without `--harvest` **and** either
  `--confirm` or an interactive `y`. It **aborts** if the estimate exceeds
  `--max-cost` (default `MAX_COST_USD` in the config block).
- No size floors — all carriers regardless of truck count.

## Pipeline

| Layer | Source | Cost |
|------|--------|------|
| 1 FMCSA spine | Company Census `az4n-8mr2`, SMS Census `kjg3-diqy`, Inspections `fx4q-ay7w` | free |
| 2 Screens | national blocklist, passenger/govt/school, private-ownership score, public hard-exclude | free |
| 3 Verticals + tire-burn | name/cargo keywords → Severe / Heavy / General | free |
| 4 Self-service score | power/driver ratio, vehicle-OOS rate vs mileage, equipment ownership → `RUNS_OWN_SHOP` | free |
| 5 Geocode + residential | Census batch geocoder, PO-box/residential split | free |
| 6 Apify deep-harvest | Google Maps + contact/email crawler + Indeed jobs | **PAID, gated** |
| 7 Output → Drive | one xlsx per metro/region, sheets by vertical + review tabs | free |
| 8 Renewal (`--diff`) | SETX-only re-pull, diff, harvest only NEW, `NEW_THIS_MONTH` sheet | free/gated |

## Usage

```sh
pip install -r intel/requirements.txt

# Free layer only — counts + cost estimate, no spend (this is the default)
python intel/scrape_fleets.py

# Quick smoke test (cap per state)
python intel/scrape_fleets.py --limit 2000

# Free layer + local xlsx workbooks
python intel/scrape_fleets.py --xlsx

# Free layer + upload workbooks to Google Drive
python intel/scrape_fleets.py --xlsx --drive

# PAID deep-harvest (top-N private-scored statewide + all SETX), capped at $25
python intel/scrape_fleets.py --harvest --confirm --max-cost 25 --xlsx --drive

# Monthly SETX renewal: diff vs last run, harvest only NEW fleets
python intel/scrape_fleets.py --diff --harvest --confirm --drive
```

## Config (top of `scrape_fleets.py`)

`STATES`, `POWER_UNITS_MIN`/`DRIVERS_MIN` (floors OFF), `HARVEST_TOP_N`,
`MAX_COST_USD`, `SETX_ZIPS`, `REGION_ZIP3`, `NATIONAL_BLOCKLIST`,
`DRIVE_FOLDER_NAME`, `SELF_SERVICE_TAG_THRESHOLD`, keyword sets, pinned
`APIFY_ACTORS`.

## Secrets — environment variables only (never committed)

| Var | Used for |
|-----|----------|
| `APIFY_TOKEN` | layer 6 harvest + live actor price reads |
| `MAPS_API_KEY` | optional Google geocode fallback |
| `GDRIVE_SERVICE_ACCOUNT_FILE` or `GDRIVE_SERVICE_ACCOUNT_JSON` | Drive upload (layer 7) |
| `SOCRATA_APP_TOKEN` | optional, raises FMCSA rate limits |

The Drive service account lives in Matt's Drive under **`GPT_MAPS/`**
(`gpt-service-account-ba0833bb7daf.json`). For GitHub Actions, paste its JSON
into the `GDRIVE_SERVICE_ACCOUNT_JSON` repo secret. The script creates the
`Oxley Fleet Intel` folder and shares it to `moxley@oxleytireinc.com`.

## Notes / honesty

- **Self-service score** uses real per-carrier vehicle out-of-service rates
  aggregated from FMCSA inspections. *Tire/brake-specific* OOS needs the
  violation-code dataset; that refinement is a documented future enrichment.
- **Residential vs commercial** at the free tier is a heuristic (PO-box / rural
  route / residential street markers + fleet size). True USPS RDI classification
  and the Apify Maps pass confirm business locations for harvested candidates.
- **Registered-agent** individual-vs-corporate detection uses FMCSA officer
  fields + a corporate-services blocklist; full agent data needs state SOS
  enrichment (future).
- Actor prices are read live from the Apify API when `APIFY_TOKEN` is set;
  documented fallbacks are used if the price isn't published per-unit.
