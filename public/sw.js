// Emberline — Service Worker
// ──────────────────────────
// CACHE_NAME and SHELL are injected at request time by server.js.
// CACHE_NAME is a SHA-256 prefix over every file listed in SHELL, so the
// cache invalidates automatically whenever any cached file changes. No
// manual version bumps, no "forgot to bump CACHE_NAME" regressions.
//
// SHELL is built from disk at server startup and includes:
//   /, /app.js, /manifest.json, /fonts/fonts.css, all /fonts/*.woff2 files,
//   /vendor/nacl-fast.min.js, /vendor/nacl-util.min.js, /icons/icon-*.png
// (entries for files that don't exist on the server are filtered out,
// so dev environments without generated icons/fonts still install cleanly).

const CACHE_NAME = 'emberline-__CACHE_VERSION__';
const SHELL      = __SHELL_LIST__;

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Never cache API routes, WebSocket upgrades, or the service worker itself.
  // sw.js is excluded so the browser always fetches a fresh copy and picks up
  // new cache versions the moment a deploy ships.
  if (url.pathname === '/challenge' ||
      url.pathname === '/count' ||
      url.pathname === '/report' ||
      url.pathname === '/sw.js' ||
      e.request.headers.get('upgrade') === 'websocket') {
    return;
  }

  // Network first for HTML (always get latest), cache fallback
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache first for static assets, network fallback
  e.respondWith(
    caches.match(e.request)
      .then(cached => cached || fetch(e.request).then(res => {
        const clone = res.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(e.request, clone));
        return res;
      }))
  );
});
