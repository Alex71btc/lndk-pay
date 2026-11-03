// The page receives its real scripts in HTML order. Only the browser boundaries,
// QR drawing and fetch are faked. An unresolved request simulates a slow server.
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const vm = require("node:vm");
const {tags, scripts} = JSON.parse(readFileSync(0, "utf8"));
const requests = [];
const draws = [];
const ready = [];
const dataKey = name => name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
function element(attrs = {}) {
  const dataset = {};
  for (const [name, value] of Object.entries(attrs)) {
    if (name.startsWith("data-")) dataset[dataKey(name)] = value;
  }
  return {
    attrs, dataset, value: attrs.value || "", textContent: "", handlers: {}, children: [],
    classList: { toggle() {} }, style: {},
    getAttribute(name) {
      return name.startsWith("data-") ? dataset[dataKey(name)] : attrs[name];
    },
    setAttribute(name, value) { attrs[name] = value; },
    addEventListener(event, callback) { this.handlers[event] = callback; },
    replaceChildren(...children) { this.children = children; },
    appendChild(child) { this.children.push(child); },
    querySelectorAll() { return []; },
  };
}
const elements = tags.map(element);
const byId = id => elements.find(el => el.attrs.id === id);
const doc = {
  readyState: "loading", documentElement: {}, createElement: () => element(),
  getElementById: byId,
  querySelectorAll(selector) {
    const match = selector.match(/^\[(data-[\w-]+)\]$/);
    return match ? elements.filter(el => Object.hasOwn(el.dataset, dataKey(match[1]))) : [];
  },
  addEventListener(event, fn) { if (event === "DOMContentLoaded") ready.push(fn); },
};
const store = new Map();
const tab = vm.createContext({
  document: doc, navigator: {languages: ["de-DE"]}, URLSearchParams,
  location: {search: "", origin: "http://localhost"}, console,
  addEventListener() {}, dispatchEvent() {}, CustomEvent: class {},
  localStorage: {getItem: k => store.get(k), setItem: (k, v) => store.set(k, v)},
  fetch(url, options) { requests.push({url, options}); return new Promise(() => {}); },
  setTimeout: () => 1, clearTimeout() {},
  QRCode: class {
    static CorrectLevel = {L: 1};
    constructor(el, options) { draws.push(options.text); }
  },
});
tab.window = tab;
for (const code of scripts) vm.runInContext(code, tab);
for (const fn of ready) fn();

assert.deepEqual(requests.map(r => r.url), ["/api/setup/status"]);
const selects = doc.querySelectorAll("[data-i18n-language]");
assert.equal(selects.length, 2);
assert.equal(selects[0].children.length, 5);
const address = "merchant@example.test";
const offer = "lno1fixture";
byId("setupBolt12Address").value = address;
byId("setupPassword").value = "editing in progress";
tab.renderQrForValue(offer, "offer");
tab.setStatus("alias.created", "ok", true, {name: "<example>"});
byId("verifyAliasDnsBtn").handlers.click(); // Button remains disabled while the request is pending.
const pending = requests.length;
assert.equal(pending, 2);
for (const [code, label] of Object.entries({
  en: "Save setup", de: "Setup speichern", es: "Guardar configuración",
  fr: "Enregistrer la configuration", pl: "Zapisz konfigurację",
})) {
  selects[0].value = code;
  selects[0].handlers.change();
  assert.equal(byId("saveSetupBtn").textContent, label);
  assert.equal(selects[1].value, code);
  assert.equal(doc.documentElement.lang, code);
  assert.equal(byId("qrModeBadge").textContent, tab.__t("qr.offer"));
  assert.equal(byId("qrValueText").textContent, offer);
  assert.equal(byId("verifyAliasDnsBtn").disabled, true);
  assert.equal(byId("verifyAliasDnsBtn").textContent, tab.__t("bip353.verify.checking"));
  assert.equal(byId("statusBar").textContent, tab.__t("alias.created", {name: "<example>"}));
  assert.equal(byId("setupBolt12Address").value, address);
  assert.equal(byId("setupPassword").value, "editing in progress");
}

const nestedDetail = tab.Bolt12I18n.ref("error.response_not_json", {status: 404});
tab.setStatus("error.initialize_detail", "error", true, {detail: nestedDetail});
for (const code of ["en", "de", "es", "fr", "pl"]) {
  selects[0].value = code;
  selects[0].handlers.change();
  assert.equal(
    byId("statusBar").textContent,
    tab.__t("error.initialize_detail", {detail: nestedDetail}),
  );
}
assert.equal(requests.length, pending, "Switching language must never issue an API request");
assert.deepEqual(draws, [offer], "Switching language must not replace the current QR code");
