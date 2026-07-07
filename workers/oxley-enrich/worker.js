// oxley-enrich — batch-enrich Tier-1 yards via Google Places API (New).
// Caches record + first photo bytes in KV (binding: ENRICH) so the maps can
// render photos/hours/phone without ever exposing the API key to the browser.
//
// Routes:
//   GET /run?key=<PLACES_KEY>[&force=1]  enrich all Tier-1 pins (skips cached
//                                        unless force=1). Key may also come from
//                                        the PLACES_KEY secret/var.
//   GET /enriched.json                   cached enriched array (CORS *)
//   GET /photo/<placeId>                 cached JPEG bytes (CORS *)
//   GET /  |  /status                    summary of what's cached
//
// Tier-1 list is embedded below. Add entries to grow it, then re-run /run.

const TIER1 = [
  { n: "LSJ Trucking Inc", a: "5020 Fannett Rd, Beaumont TX", t: 30.0377, g: -94.1468 },
  { n: "KDSI Trucking Inc", a: "190 S 4th St, Beaumont, TX 77701", t: 30.0773108, g: -94.1156712 },
  { n: "Beaumont Iron & Metal", a: "3190 Hollywood St, Beaumont, TX 77701", t: 30.0753545, g: -94.1231927 },
  { n: "C & T Trucking", a: "4240 Cadillac Ln, Beaumont TX", t: 30.0454, g: -94.1009 },
  { n: "CURTIS & SON VACUUM SERVICE INC", a: "4408 NORTH MAIN STREET, LIBERTY 77575", t: 30.09021, g: -94.75877 },
  { n: "SUPERIOR WASTE SOLUTIONS LLC", a: "5565 ERIE ST, BEAUMONT 77705", t: 30.032367, g: -94.100749 },
  { n: "SMART OILFIELD SERVICES LLC", a: "2251 MIZELL RD, LIBERTY 77575", t: 30.07959, g: -94.77106 },
  { n: "MODERN CONCRETE & MATERIALS LLC", a: "4825 ROMEDA ROAD, BEAUMONT 77705", t: 30.039152, g: -94.123525 },
  { n: "CLEARSTREAM WASTEWATER SYSTEMS INC", a: "4899 US HWY 69 S, LUMBERTON 77657", t: 30.186543, g: -94.186762 },
  { n: "IMPACT WASTE LLC", a: "6315 N HWY 347, BEAUMONT 77720", t: 30.021073, g: -94.048237 },
  { n: "INTEGRITY READY MIX CONCRETE LLC", a: "1288A FOSTORIA RD, CLEVELAND 77328", t: 30.339193, g: -95.166425 },
  { n: "CURTIS OILFIELD SERVICES LLC", a: "4779 US HWY 96 NORTH, SILSBEE 77656", t: 30.356908, g: -94.109959 },
  { n: "BIOMEDICAL WASTE SOLUTIONS", a: "9665 JADE AVE, PORT ARTHUR 77642", t: 29.927078, g: -94.031777 },
  { n: "PARKS LEASE & VACUUM SERVICE LP", a: "27194 HWY 96, KIRBYVILLE 75956", t: 30.549054, g: -93.931907 },
  { n: "SANDIFER'S LP GAS AND SERVICE CO INC", a: "5812 GULFWAY DRIVE, PORT ARTHUR 77642", t: 29.925645, g: -93.906019 },
  { n: "MARTINEZ CARGO LOGISTICS LLC", a: "275 RD 3554, CLEVELAND 77327", t: 30.181552, g: -95.09043 },
  { n: "YELLOW JACKET DAYTON READYMIX LLC", a: "3303 BEAUMONT AVE, LIBERTY 77575", t: 30.059747, g: -94.770132 },
  { n: "E5IVE LOGISTICS LLC", a: "1022 MAGNOLIA AVE, PORT NECHES 77651", t: 29.980781, g: -93.963789 },
  { n: "BENDY LOGISTICS LLC", a: "3985 MARIE ST, BEAUMONT 77705", t: 30.04785, g: -94.106267 },
  { n: "LIBERTY READY MIX LP", a: "3033 BEAUMONT AVENUE, LIBERTY 77575", t: 30.059628, g: -94.777413 },
  { n: "MR GARBAGE LLC", a: "4745 FANNETT RD, BEAUMONT 77705", t: 30.039985, g: -94.13718 },
  { n: "READ LOGGING INC", a: "208 CR 1308, WARREN 77664", t: 30.622342, g: -94.41215 },
  { n: "CRANE TECH LOGISTICS INC", a: "16415 HIGHWAY 90, BEAUMONT 77713", t: 30.052274, g: -94.299934 },
  { n: "M&S HEAVY HAUL LLC", a: "101 FM HIGHWAY 365, PORT ARTHUR 77640", t: 29.924841, g: -94.014421 },
  { n: "WILTEX LOGISTICS LLC", a: "1600 CEDAR ST, BEAUMONT 77701", t: 30.077294, g: -94.111689 },
  { n: "PERYN HEAVY HAUL LLC", a: "500 MOCKINGBIRD, VIDOR 77662", t: 30.109396, g: -94.048748 },
  { n: "COASTLINE CONCRETE PUMPING LLC", a: "910 N ROSE CITY DR, VIDOR 77662", t: 30.101955, g: -94.063803 },
  { n: "2S ROLL OFF SERVICE LLC", a: "6642 INDUSTRIAL ROAD, BEAUMONT 77705", t: 29.989231, g: -94.204504 },
  { n: "A VALDEZ LOGISTICS LLC", a: "507 COUNTY RD 4861, DAYTON 77535", t: 29.955386, g: -94.944741 },
  { n: "LONESTAR TRUCKING AND LOGISTICS LLC", a: "2115 AVENUE L, NEDERLAND 77627", t: 29.962094, g: -93.985855 },
  { n: "PAUL GREER LOGGING INC", a: "9208 US HWY 69 SOUTH, WARREN 77664", t: 30.651066, g: -94.397744 },
  { n: "GLOBAL RHINO READY MIX RR LLC", a: "8375 CHEMICAL RD, BEAUMONT 77705", t: 29.990298, g: -94.198848 },
  { n: "NAVTRANS LOGISTICS LLC", a: "11065 FM 1008, DAYTON 77535", t: 30.198338, g: -94.909138 },
  { n: "DDH LOGISTICS LLC", a: "1990 DRISKILL ST, BEAUMONT 77706", t: 30.10026, g: -94.13857 },
  { n: "TRIANGLE CONCRETE SERVICES INC", a: "1350 S MAJOR DR, BEAUMONT 77707", t: 30.062467, g: -94.189619 },
];

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, OPTIONS",
  "access-control-allow-headers": "*",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS },
  });

const DETAIL_MASK = [
  "id", "displayName", "formattedAddress", "location",
  "nationalPhoneNumber", "internationalPhoneNumber",
  "regularOpeningHours.weekdayDescriptions",
  "rating", "userRatingCount", "websiteUri", "googleMapsUri", "photos.name",
].join(",");

async function enrichOne(pin, key, env) {
  // 1) Text Search biased to the pin location -> best matching place.
  const searchRes = await fetch("https://places.googleapis.com/v1/places:searchText", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Goog-Api-Key": key,
      "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress",
    },
    body: JSON.stringify({
      textQuery: pin.n + " " + (pin.a || ""),
      locationBias: { circle: { center: { latitude: pin.t, longitude: pin.g }, radius: 4000 } },
      maxResultCount: 1,
    }),
  });
  if (!searchRes.ok) {
    return { n: pin.n, ok: false, stage: "searchText", status: searchRes.status, detail: (await searchRes.text()).slice(0, 300) };
  }
  const search = await searchRes.json();
  const hit = search.places && search.places[0];
  if (!hit) return { n: pin.n, ok: false, stage: "searchText", status: 200, detail: "no place match" };

  // 2) Place Details.
  const detRes = await fetch("https://places.googleapis.com/v1/places/" + hit.id, {
    headers: { "X-Goog-Api-Key": key, "X-Goog-FieldMask": DETAIL_MASK },
  });
  if (!detRes.ok) {
    return { n: pin.n, ok: false, stage: "details", status: detRes.status, detail: (await detRes.text()).slice(0, 300) };
  }
  const det = await detRes.json();

  // 3) First photo -> cache bytes in KV (served via /photo/<placeId>).
  let hasPhoto = false;
  const photoName = det.photos && det.photos[0] && det.photos[0].name;
  if (photoName) {
    const media = await fetch("https://places.googleapis.com/v1/" + photoName + "/media?maxWidthPx=1000&key=" + key);
    if (media.ok && (media.headers.get("content-type") || "").startsWith("image/")) {
      const bytes = await media.arrayBuffer();
      await env.ENRICH.put("photo:" + det.id, bytes, {
        metadata: { contentType: media.headers.get("content-type") || "image/jpeg" },
      });
      hasPhoto = true;
    }
  }

  const record = {
    n: pin.n,
    placeId: det.id,
    displayName: (det.displayName && det.displayName.text) || pin.n,
    address: det.formattedAddress || pin.a || "",
    phone: det.nationalPhoneNumber || det.internationalPhoneNumber || "",
    hours: (det.regularOpeningHours && det.regularOpeningHours.weekdayDescriptions) || [],
    rating: det.rating || null,
    ratingCount: det.userRatingCount || null,
    website: det.websiteUri || "",
    mapsUri: det.googleMapsUri || "",
    lat: (det.location && det.location.latitude) || pin.t,
    lng: (det.location && det.location.longitude) || pin.g,
    photo: hasPhoto ? "/photo/" + det.id : null,
    enrichedAt: new Date().toISOString(),
  };
  await env.ENRICH.put("rec:" + det.id, JSON.stringify(record));
  return { n: pin.n, ok: true, placeId: det.id, photo: hasPhoto };
}

async function readIndex(env) {
  const list = await env.ENRICH.list({ prefix: "rec:" });
  const out = [];
  for (const k of list.keys) {
    const v = await env.ENRICH.get(k.name);
    if (v) out.push(JSON.parse(v));
  }
  return out;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (url.pathname === "/run") {
      const key = url.searchParams.get("key") || (env && env.PLACES_KEY) || "";
      if (!key) return json({ error: "provide ?key=<PLACES_KEY> (Places API New enabled)" }, 400);
      const force = url.searchParams.get("force") === "1";
      // Cloudflare caps subrequests per invocation (50 on the free plan) and each
      // pin costs up to 3, so enrich at most `limit` uncached pins per call and
      // track finished pins in a single "done" key (cheap skip-check, no re-charge).
      const limit = Math.max(1, parseInt(url.searchParams.get("limit") || "12", 10));
      let done = [];
      if (!force) { try { done = JSON.parse((await env.ENRICH.get("done")) || "[]"); } catch (e) { done = []; } }
      const doneSet = new Set(done);
      const results = [];
      let processed = 0, remaining = 0;
      for (const pin of TIER1) {
        if (doneSet.has(pin.n)) continue;
        if (processed >= limit) { remaining++; continue; }
        processed++;
        try {
          const r = await enrichOne(pin, key, env);
          results.push(r);
          // Mark done on success, or on a definitive "no place match" (won't improve on retry).
          if (r && (r.ok || (r.stage === "searchText" && r.status === 200))) doneSet.add(pin.n);
        } catch (e) {
          results.push({ n: pin.n, ok: false, stage: "exception", detail: String(e && e.message || e) });
        }
      }
      await env.ENRICH.put("done", JSON.stringify([...doneSet]));
      return json({ processed: results.length, enrichedTotal: doneSet.size, remaining, results });
    }

    if (url.pathname === "/enriched.json") {
      return json(await readIndex(env));
    }

    if (url.pathname.startsWith("/photo/")) {
      const id = decodeURIComponent(url.pathname.slice("/photo/".length));
      const { value, metadata } = await env.ENRICH.getWithMetadata("photo:" + id, { type: "arrayBuffer" });
      if (!value) return new Response("not found", { status: 404, headers: CORS });
      return new Response(value, {
        headers: {
          "content-type": (metadata && metadata.contentType) || "image/jpeg",
          "cache-control": "public, max-age=86400",
          ...CORS,
        },
      });
    }

    // status
    const idx = await readIndex(env);
    return json({
      worker: "oxley-enrich",
      tier1: TIER1.map((p) => p.n),
      cached: idx.map((r) => ({ n: r.n, placeId: r.placeId, photo: !!r.photo, phone: !!r.phone, hours: r.hours.length })),
      endpoints: ["/run?key=…", "/enriched.json", "/photo/<placeId>"],
    });
  },
};
