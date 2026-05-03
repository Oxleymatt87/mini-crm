// Territory XR service worker.
//
// Goals:
//   1. Make /map-xr.html installable as a standalone PWA on the Galaxy
//      XR headset by satisfying the installability criteria (start_url +
//      icons + a fetch handler).
//   2. Cache the shell + JS module deps so the AR experience boots
//      offline once it has been opened on Wi-Fi.
//   3. Stay out of the way of dynamic data: Firestore, auth, and the
//      session-token Google 3D tile fetches must always go to network.

const VERSION = 'v3';
const CACHE = `territory-xr-${VERSION}`;

// Same-origin shell. Listed individually so install() fails loudly if
// any of them 404 — that's the signal we deployed an inconsistent build.
const SHELL = [
  '/',
  '/map-xr.html',
  '/map.html',
  '/index.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

// Cross-origin module deps. We pre-fetch them with mode:'no-cors' so
// install() succeeds even when esm.sh / gstatic don't return CORS
// headers for the bare GET. Runtime fetch handler will refresh them.
const MODULES = [
  'https://esm.sh/three@0.160.0',
  'https://esm.sh/three@0.160.0/examples/jsm/controls/OrbitControls.js',
  'https://esm.sh/3d-tiles-renderer@0.3.39?deps=three@0.160.0',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-auth-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore-compat.js'
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // Same-origin: strict — failure here means a broken deploy.
    await cache.addAll(SHELL);
    // Cross-origin: best-effort. Some CDNs vary by query string or
    // serve opaque responses; we settle individually so one bad URL
    // doesn't tank the whole install.
    await Promise.all(MODULES.map(async url => {
      try {
        const res = await fetch(url, { mode: 'no-cors' });
        await cache.put(url, res);
      } catch (_) {}
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

// Domains we never want to cache — always go to network so live data
// stays live and Google's 3D-tile session tokens stay valid.
function isDynamic(url) {
  const h = url.hostname;
  return (
    h.includes('firestore.googleapis.com') ||
    h.includes('firebaseio.com') ||
    h.includes('identitytoolkit.googleapis.com') ||
    h.includes('securetoken.googleapis.com') ||
    h.includes('tile.googleapis.com')
  );
}

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (isDynamic(url)) return; // let the network handle it

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(req);
    // Stale-while-revalidate: serve cache immediately if present, then
    // refresh in the background. On miss, fetch + cache + return.
    const network = fetch(req).then(res => {
      // Don't cache opaque error responses or partial content.
      if (res && (res.ok || res.type === 'opaque')) {
        cache.put(req, res.clone()).catch(() => {});
      }
      return res;
    }).catch(() => cached);
    return cached || network;
  })());
});

// Allow the page to trigger a controlled refresh after deploy.
self.addEventListener('message', event => {
  if (event.data === 'skip-waiting') self.skipWaiting();
});
