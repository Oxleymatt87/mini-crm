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
  { n: "LSJ Trucking Inc",        a: "5020 Fannett Rd, Beaumont TX",         t: 30.0377,    g: -94.1468 },
  { n: "KDSI Trucking Inc",       a: "190 S 4th St, Beaumont, TX 77701",     t: 30.0773108, g: -94.1156712 },
  { n: "Beaumont Iron & Metal",   a: "3190 Hollywood St, Beaumont, TX 77701", t: 30.0753545, g: -94.1231927 },
  { n: "C & T Trucking",          a: "4240 Cadillac Ln, Beaumont TX",        t: 30.0454,    g: -94.1009 },
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
      const results = [];
      for (const pin of TIER1) {
        try {
          if (!force) {
            // skip if we already have a record whose original name matches
            const existing = await readIndex(env);
            if (existing.some((r) => r.n === pin.n)) { results.push({ n: pin.n, ok: true, skipped: "cached" }); continue; }
          }
          results.push(await enrichOne(pin, key, env));
        } catch (e) {
          results.push({ n: pin.n, ok: false, stage: "exception", detail: String(e && e.message || e) });
        }
      }
      return json({ ran: results.length, results });
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
