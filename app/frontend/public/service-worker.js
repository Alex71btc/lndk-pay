self.addEventListener("install", (event) => {
  self.skipWaiting();
});

const LEGACY_CACHE_PREFIX = "bolt12-pay-";

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then((keys) =>
        Promise.all(
          keys
            .filter((key) => key.startsWith(LEGACY_CACHE_PREFIX))
            .map((key) => caches.delete(key)),
        ),
      ),
      self.clients.claim(),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  // Keep requests network-only. Chrome's programmatic PWA install prompt still
  // requires an effective fetch handler and ignores an empty listener.
  event.respondWith(fetch(event.request));
});
