/* Attach the CSRF token to every same-origin state-changing request.
 *
 * The server requires X-CSRF-Token (matching the csrf_token cookie) on every
 * authenticated POST/PUT/PATCH/DELETE under /api/. Loaded first on the Pay and
 * Console pages so individual call sites cannot forget it. */
(() => {
  "use strict";
  const nativeFetch = window.fetch.bind(window);
  const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

  function csrfToken() {
    const row = document.cookie.split("; ").find((entry) => entry.startsWith("csrf_token="));
    return row ? decodeURIComponent(row.slice("csrf_token=".length)) : "";
  }

  window.fetch = function fetchWithCsrf(input, init = {}) {
    const request = input instanceof Request ? input : null;
    const method = String(init.method || request?.method || "GET").toUpperCase();
    const url = new URL(request ? request.url : String(input), window.location.href);
    if (safeMethods.has(method) || url.origin !== window.location.origin) {
      return nativeFetch(input, init);
    }
    const headers = new Headers(init.headers || request?.headers || undefined);
    if (!headers.has("X-CSRF-Token")) {
      const token = csrfToken();
      if (token) headers.set("X-CSRF-Token", token);
    }
    return nativeFetch(input, { ...init, headers });
  };
})();
