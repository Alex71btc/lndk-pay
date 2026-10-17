self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  // Keep requests network-only. Chrome's programmatic PWA install prompt still
  // requires an effective fetch handler and ignores an empty listener.
  event.respondWith(fetch(event.request));
});
