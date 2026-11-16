/* Shared authenticated incoming-payment notifications. */
(() => {
  'use strict';
  if (!['/pay', '/app'].includes(location.pathname)) return;
  const paymentToastRegion = document.createElement('div');
  paymentToastRegion.className = 'paymentToastRegion';
  paymentToastRegion.setAttribute('aria-live', 'polite');
  paymentToastRegion.setAttribute('aria-relevant', 'additions');
  document.body.appendChild(paymentToastRegion);
      const INCOMING_PAYMENT_SEEN_STORAGE_KEY =
        "bolt12pay.incoming-payment-toast.seen.v1";
      const INCOMING_PAYMENT_SEEN_LIMIT = 250;
      const INCOMING_PAYMENT_RECENCY_GRACE_MS = 5000;
      const incomingPaymentMonitoringStartedAt = (() => {
        try { return Number(sessionStorage.getItem('bolt12pay.incoming-payment-toast.checked')) || Date.now(); }
        catch (_) { return Date.now(); }
      })();
      let incomingPaymentBaselineReady = false;

      function loadSeenIncomingPaymentIds() {
        try {
          const stored = JSON.parse(
            sessionStorage.getItem(INCOMING_PAYMENT_SEEN_STORAGE_KEY) || "[]",
          );
          return new Set(
            Array.isArray(stored)
              ? stored.filter((value) => typeof value === "string")
              : [],
          );
        } catch {
          return new Set();
        }
      }

      const seenIncomingPaymentIds = loadSeenIncomingPaymentIds();
      try { incomingPaymentBaselineReady = sessionStorage.getItem(INCOMING_PAYMENT_SEEN_STORAGE_KEY) !== null; } catch (_) {}

      function incomingPaymentId(item) {
        if (item?.direction !== "incoming" || item?.status !== "settled") {
          return "";
        }
        return String(item.payment_hash || "").trim().toLowerCase();
      }

      function incomingPaymentIsRecent(item) {
        const settledAt =
          parseTxTimestamp(item?.settled_at) ||
          parseTxTimestamp(item?.created_at);
        return (
          !settledAt ||
          settledAt.getTime() >=
            incomingPaymentMonitoringStartedAt -
              INCOMING_PAYMENT_RECENCY_GRACE_MS
        );
      }

      function persistSeenIncomingPaymentIds() {
        try {
          const recentIds = Array.from(seenIncomingPaymentIds).slice(
            -INCOMING_PAYMENT_SEEN_LIMIT,
          );
          sessionStorage.setItem(
            INCOMING_PAYMENT_SEEN_STORAGE_KEY,
            JSON.stringify(recentIds),
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

      async function openIncomingPaymentInActivity(paymentHash) {
        window.location.assign('/pay?view=activity&payment=' + encodeURIComponent(paymentHash));
      }

      function showIncomingPaymentToast(item, paymentHash) {
        if (!paymentToastRegion) return;

        const amount = plainSatsValue(item.amount_sat);
        const category = incomingPaymentCategory(item);
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
            await openIncomingPaymentInActivity(paymentHash);
          } catch (error) {
            console.error("Failed to open incoming payment", error);
          }
        });
        paymentToastRegion.appendChild(button);
      }

      function processIncomingPaymentNotifications(items) {
        const settledIncoming = (Array.isArray(items) ? items : [])
          .map((item) => ({ item, id: incomingPaymentId(item) }))
          .filter(({ id }) => Boolean(id));

        if (!incomingPaymentBaselineReady) {
          for (const { id } of settledIncoming) seenIncomingPaymentIds.add(id);
          incomingPaymentBaselineReady = true;
          persistSeenIncomingPaymentIds();
          return [];
        }

        const unseenPayments = settledIncoming.filter(
          ({ id }) => !seenIncomingPaymentIds.has(id),
        );
        for (const { id } of unseenPayments) seenIncomingPaymentIds.add(id);

        // A server restart can backfill older LND history after the page has
        // already established an empty baseline. Remember those rows without
        // presenting them as newly received browser events.
        const newPayments = unseenPayments
          .filter(({ item }) => incomingPaymentIsRecent(item))
          .reverse();

        for (const { item, id } of newPayments) {
          showIncomingPaymentToast(item, id);
        }
        if (unseenPayments.length) persistSeenIncomingPaymentIds();
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
  async function poll() {
    if (stopped) return;
    try {
      const response = await fetch('/api/tx-history?limit=200', {credentials:'same-origin', cache:'no-store'});
      if ([401,403].includes(response.status)) {
        stopped = true;
        paymentToastRegion.replaceChildren();
        try {
          sessionStorage.removeItem(INCOMING_PAYMENT_SEEN_STORAGE_KEY);
          sessionStorage.removeItem('bolt12pay.incoming-payment-toast.checked');
        } catch (_) {}
        return;
      }
      if (response.ok) {
        processIncomingPaymentNotifications((await response.json()).items || []);
        try { sessionStorage.setItem('bolt12pay.incoming-payment-toast.checked', String(Date.now())); } catch (_) {}
      }
    } catch (_) { /* Retry transient network errors, never invent events. */ }
    if (!stopped) window.setTimeout(poll, 5000);
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) paymentToastRegion.replaceChildren();
  });
  poll();
})();
