/* Shared authenticated incoming-payment notifications. */
(() => {
  'use strict';
  if (!['/pay', '/app'].includes(location.pathname)) return;
  if (window.__bolt12PaymentNotificationsStarted) return;
  window.__bolt12PaymentNotificationsStarted = true;
  const paymentToastRegion = document.createElement('div');
  paymentToastRegion.className = 'paymentToastRegion';
  paymentToastRegion.setAttribute('aria-live', 'polite');
  paymentToastRegion.setAttribute('aria-relevant', 'additions');
  document.body.appendChild(paymentToastRegion);
      // Shared across tabs and page navigation. v1 used sessionStorage, whose
      // copied tab snapshots replayed payments already shown in another view.
      const INCOMING_PAYMENT_SEEN_STORAGE_KEY =
        "bolt12pay.incoming-payment-toast.state.v2";
      const INCOMING_PAYMENT_SEEN_LIMIT = 250;
      const INCOMING_PAYMENT_RECENCY_GRACE_MS = 5000;
      const INCOMING_PAYMENT_MAX_CATCHUP_MS = 30000;
      const incomingPaymentPageOpenedAt = Date.now();
      let incomingPaymentMonitoringStartedAt = incomingPaymentPageOpenedAt;
      let incomingPaymentBaselineReady = false;
      const seenIncomingPaymentIds = new Set();
      let paymentToastStorage;
      try {
        paymentToastStorage = localStorage;
        // Access can throw when browser storage is disabled.
        paymentToastStorage.getItem(INCOMING_PAYMENT_SEEN_STORAGE_KEY);
      } catch (_) {
        try { paymentToastStorage = sessionStorage; } catch (_) {}
      }

      function refreshSeenIncomingPaymentIds() {
        try {
          const stored = JSON.parse(
            paymentToastStorage?.getItem(INCOMING_PAYMENT_SEEN_STORAGE_KEY) || "null",
          );
          if (!stored || !Array.isArray(stored.ids)) return;
          for (const id of stored.ids) {
            if (typeof id === "string") seenIncomingPaymentIds.add(id);
          }
          // Only a recently active view can hand over live monitoring. A new
          // browser session establishes a baseline instead of replaying history.
          if (!incomingPaymentBaselineReady &&
              Number(stored.checkedAt) >= incomingPaymentPageOpenedAt - INCOMING_PAYMENT_MAX_CATCHUP_MS) {
            incomingPaymentBaselineReady = true;
            incomingPaymentMonitoringStartedAt = Math.min(
              incomingPaymentPageOpenedAt,
              Number(stored.startedAt) || Number(stored.checkedAt),
            );
          }
        } catch (_) { /* Malformed or unavailable storage becomes a new baseline. */ }
      }

      function incomingPaymentId(item) {
        if (item?.direction !== "incoming" || item?.status !== "settled") {
          return "";
        }
        const hash = String(item.payment_hash || "").trim().toLowerCase();
        if (!hash) return '';
        return item.backend_id && item.backend_id !== 'lnd-default' ? `${item.backend_id}:${hash}` : hash;
      }

      function incomingPaymentIsRecent(item) {
        const settledAt =
          parseTxTimestamp(item?.settled_at) ||
          parseTxTimestamp(item?.created_at);
        return (
          settledAt &&
          settledAt.getTime() >=
            incomingPaymentMonitoringStartedAt - INCOMING_PAYMENT_RECENCY_GRACE_MS
        );
      }

      function persistSeenIncomingPaymentIds() {
        try {
          const allIds = Array.from(seenIncomingPaymentIds);
          const recentIds = allIds.slice(-INCOMING_PAYMENT_SEEN_LIMIT);
          for (const id of allIds.slice(0, -INCOMING_PAYMENT_SEEN_LIMIT)) {
            seenIncomingPaymentIds.delete(id);
          }
          paymentToastStorage?.setItem(
            INCOMING_PAYMENT_SEEN_STORAGE_KEY,
            JSON.stringify({ids: recentIds, checkedAt: Date.now(),
              startedAt: incomingPaymentMonitoringStartedAt}),
          );
        } catch {}
      }

      function plainSatsValue(value) {
        const numericValue = Number(value);
        if (!Number.isFinite(numericValue)) return "0";
        return String(Math.max(0, Math.trunc(numericValue)));
      }

      function incomingPaymentCategory(item) {
        const method = String(item?.method || "").trim().toLowerCase();
        const paymentType = String(item?.type || "").trim().toLowerCase();

        if (method === "zap" || paymentType === "zap") {
          return window.__t("history.nostr_zap");
        }
        if (
          method === "bolt12" ||
          method === "offer" ||
          paymentType === "offer"
        ) {
          return window.__t("history.bolt12_offer");
        }

        const translationKey = {
          lightning_address: "history.lightning_address",
          lnurl: "history.lnurl",
          bolt11: "history.bolt11_invoice",
          bolt11_alias_fallback: "history.bolt11_invoice",
          keysend: "history.keysend",
        }[method];
        return translationKey ? window.__t(translationKey) : "";
      }

      async function openIncomingPaymentInActivity(paymentHash, backendId) {
        window.location.assign('/pay?view=activity&payment=' + encodeURIComponent(paymentHash)
          + (backendId ? '&backend=' + encodeURIComponent(backendId) : ''));
      }

      function showIncomingPaymentToast(item, paymentHash) {
        if (!paymentToastRegion) return;

        const amount = plainSatsValue(item.amount_sat);
        const backend = window.__t(String(item.backend_id || 'lnd-default').startsWith('phoenixd-')
          ? 'backend.name_phoenixd' : 'backend.name_lnd');
        const category = [incomingPaymentCategory(item), backend].filter(Boolean).join(' · ');
        const comment = String(item.notification_comment || "").trim();
        const button = document.createElement("button");
        button.type = "button";
        button.className = "paymentToast";
        button.title = window.__t("toast.open_payment_activity");
        button.setAttribute(
          "aria-label",
          window.__t("toast.open_payment_activity_amount", { amount }),
        );

        const title = document.createElement("span");
        title.className = "paymentToastTitle";
        title.dataset.i18n = "toast.payment_received";
        title.dataset.i18nParams = JSON.stringify({amount});
        title.textContent = window.__t("toast.payment_received", { amount });
        button.appendChild(title);

        if (category) {
          const categoryElement = document.createElement("span");
          categoryElement.className = "paymentToastCategory";
          categoryElement.textContent = category;
          button.appendChild(categoryElement);
        }

        if (comment) {
          const commentElement = document.createElement("span");
          commentElement.className = "paymentToastComment";
          commentElement.textContent = comment;
          button.appendChild(commentElement);
        }

        const dismissTimer = window.setTimeout(() => button.remove(), 10000);
        button.addEventListener("click", async () => {
          window.clearTimeout(dismissTimer);
          button.remove();
          try {
            await openIncomingPaymentInActivity(String(item.payment_hash || ''), item.backend_id);
          } catch (error) {
            console.error("Failed to open incoming payment", error);
          }
        });
        paymentToastRegion.appendChild(button);
        while (paymentToastRegion.children.length > 3) {
          paymentToastRegion.children[0].remove();
        }
      }

      function processIncomingPaymentNotifications(items) {
        refreshSeenIncomingPaymentIds();
        const settledIncoming = (Array.isArray(items) ? items : [])
          .map((item) => ({ item, id: incomingPaymentId(item) }))
          .filter(({ id }) => Boolean(id));

        if (!incomingPaymentBaselineReady) {
          for (const { id } of settledIncoming) seenIncomingPaymentIds.add(id);
          incomingPaymentBaselineReady = true;
          persistSeenIncomingPaymentIds();
          return [];
        }

        const unseenPayments = [];
        for (const entry of settledIncoming) {
          if (seenIncomingPaymentIds.has(entry.id)) continue;
          // Claim immediately: duplicate rows within one response must not
          // create two toasts before the remembered IDs have been updated.
          seenIncomingPaymentIds.add(entry.id);
          unseenPayments.push(entry);
        }

        // A server restart can backfill older LND history after the page has
        // already established an empty baseline. Remember those rows without
        // presenting them as newly received browser events.
        const newPayments = unseenPayments
          .filter(({ item }) => incomingPaymentIsRecent(item))
          .reverse();

        for (const { item, id } of newPayments) {
          showIncomingPaymentToast(item, id);
        }
        persistSeenIncomingPaymentIds();
        return newPayments.map(({ id }) => id);
      }

      function parseTxTimestamp(value) {
        if (value === null || value === undefined) return null;

        const rawValue = String(value).trim();
        if (!rawValue) return null;

        let date;

        if (/^\d+(?:\.\d+)?$/.test(rawValue)) {
          const numericValue = Number(rawValue);
          if (!Number.isFinite(numericValue) || numericValue <= 0) {
            return null;
          }

          let milliseconds = numericValue * 1000;
          if (numericValue >= 1e17) {
            milliseconds = numericValue / 1e6;
          } else if (numericValue >= 1e14) {
            milliseconds = numericValue / 1e3;
          } else if (numericValue >= 1e11) {
            milliseconds = numericValue;
          }

          date = new Date(milliseconds);
        } else {
          date = new Date(rawValue);
        }

        return Number.isNaN(date.getTime()) ? null : date;
      }
  let stopped = false;
  let polling = false;
  let pollTimer;
  function schedulePoll() {
    window.clearTimeout(pollTimer);
    if (!stopped) pollTimer = window.setTimeout(poll, 5000);
  }
  async function poll() {
    if (stopped || polling) return;
    window.clearTimeout(pollTimer);
    if (document.hidden) {
      schedulePoll();
      return;
    }
    polling = true;
    try {
      const response = await fetch('/api/tx-history?limit=200', {credentials:'same-origin', cache:'no-store'});
      if ([401,403].includes(response.status)) {
        stopped = true;
        paymentToastRegion.replaceChildren();
        // Keep hash-only deduplication across sign-in; never persist details.
        return;
      }
      if (response.ok) {
        const items = (await response.json()).items || [];
        // A hidden tab must not consume notifications intended for the visible
        // Pay, Console or Setup view, including when focus changed mid-request.
        const process = () => {
          if (!document.hidden) processIncomingPaymentNotifications(items);
        };
        if (typeof navigator !== 'undefined' && navigator.locks?.request) {
          await navigator.locks.request(INCOMING_PAYMENT_SEEN_STORAGE_KEY, process);
        } else {
          process();
        }
      }
    } catch (_) { /* Retry transient network errors, never invent events. */ }
    finally {
      polling = false;
      schedulePoll();
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) paymentToastRegion.replaceChildren();
    else poll();
  });
  poll();
})();
