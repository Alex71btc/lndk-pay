// Execute the shipped /pay inline scripts and catalogs. Keep setup/config pending
// to exercise language changes without connecting to any backend or wallet.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { tags, scripts } = JSON.parse(fs.readFileSync(0, "utf8"));
const elements = [];
const events = new Map();
const requests = [];
const stored = new Map();
const keyFor = (attr) => attr.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
function element(attrs = {}) {
  const dataset = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith("data-")) dataset[keyFor(key)] = value;
  }
  const el = {
    attrs, dataset, children: [], value: attrs.value || "", textContent: "", innerHTML: "",
    classList: {toggle() {}, contains() { return false; }, add() {}, remove() {}},
    style: {setProperty() {}}, handlers: new Map(),
    addEventListener(type, callback) { this.handlers.set(type, callback); },
    getAttribute(key) { return key.startsWith("data-") ? dataset[keyFor(key)] : attrs[key]; },
    setAttribute(key, value) { attrs[key] = value; },
    replaceChildren(...children) { this.children = children; },
    appendChild(child) { this.children.push(child); },
    querySelector() { return null; }, querySelectorAll() { return []; },
    matches() { return false; },
  };
  elements.push(el);
  return el;
}
tags.forEach(element);
const byId = id => elements.find(el => el.attrs.id === id);
const ready = [];
const document = {
  documentElement: element(), readyState: "loading", getElementById: byId,
  querySelector() { return null; },
  querySelectorAll(selector) {
    const attr = selector.match(/^\[(data-[\w-]+)\]$/);
    return attr ? elements.filter(el => Object.hasOwn(el.dataset, keyFor(attr[1]))) : [];
  },
  createElement() { return element(); },
  addEventListener(type, callback) { if (type === "DOMContentLoaded") ready.push(callback); },
};
const tab = vm.createContext({
  document, navigator: {languages: ["de-DE"]}, URLSearchParams, URL, console,
  localStorage: {getItem: k => stored.get(k), setItem: (k,v) => stored.set(k,v)},
  setTimeout() { return 1; }, clearTimeout() {}, setInterval() { return 1; }, clearInterval() {},
  requestAnimationFrame() { return 1; }, cancelAnimationFrame() {},
  location: {search: "", origin: "http://localhost", hash: ""},
  CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; }},
  addEventListener(type, callback) {
    if (!events.has(type)) events.set(type, []);
    events.get(type).push(callback);
  },
  dispatchEvent(event) { for (const callback of events.get(event.type) || []) callback(event); },
  fetch(url) { requests.push(url); return new Promise(() => {}); },
});
tab.window = tab;
for (const js of scripts) vm.runInContext(js, tab);
ready[0](); // Apply static translations through the shared DOMContentLoaded listener.
assert.deepEqual(requests, ["/api/setup/config"]);
const target = "alice@example.test";
byId("payOfferInput").value = target;
byId("payAmountInput").value = "123";
byId("payerNoteInput").value = "keep <private> & exact";
tab.setCurrentOffer("lno1activefixture");
tab.showErrorDetail("HTTP 503");
const selector = document.querySelectorAll("[data-i18n-language]")[0];
assert.equal(selector.children.length, 5);
for (const code of ["en", "de", "es", "fr", "pl"]) {
  selector.value = code;
  selector.handlers.get("change")();
  assert.equal(document.documentElement.lang, code);
  assert.equal(byId("qrModeBadge").textContent, tab.__t("badge.qr_offer"));
  assert.equal(byId("statusBar").textContent, tab.__t("error.detail", {message: "HTTP 503"}));
  assert.equal(byId("offerPreviewBox").textContent, "lno1activefixture");
  assert.equal(byId("payOfferInput").value, target);
  assert.equal(byId("payAmountInput").value, "123");
  assert.equal(byId("payerNoteInput").value, "keep <private> & exact");
  assert.equal(byId("txHistoryList").children.at(-1).textContent, tab.__t("history.no_transactions"));
  assert.deepEqual(requests, ["/api/setup/config"], "Language selection performed a network request");
}
