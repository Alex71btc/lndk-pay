(function (global) {
  "use strict";

  const languages = Object.freeze({
    en: "English", de: "Deutsch", es: "Español", fr: "Français", pl: "Polski",
  });
  const catalogs = Object.create(null);
  const storageKey = "app_lang";
  let scope = "";

  function normalize(value) {
    const code = String(value || "").toLowerCase().split(/[-_]/)[0];
    return Object.hasOwn(languages, code) ? code : null;
  }

  function detectLanguage() {
    try {
      const stored = global.localStorage.getItem(storageKey);
      if (stored) return normalize(stored) || "en";
    } catch (_) { /* Private browsing may disable storage. */ }
    const preferred = global.navigator.languages || [global.navigator.language];
    for (const candidate of preferred) {
      const supported = normalize(candidate);
      if (supported) return supported;
    }
    return "en";
  }

  let language = detectLanguage();

  function ref(key, values = {}) {
    return { i18nKey: String(key), values };
  }

  function resolveValue(value, namespace) {
    if (value && typeof value === "object" && Object.hasOwn(value, "i18nKey")) {
      return translate(value.i18nKey, value.values || {}, namespace);
    }
    return value;
  }

  function translate(key, values = {}, namespace = scope) {
    const catalog = catalogs[namespace] || {};
    const localized = catalog[language] || {};
    const english = catalog.en || {};
    const template = (Object.hasOwn(localized, key) && localized[key]) ||
      (Object.hasOwn(english, key) && english[key]) || key;
    return String(template).replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (match, name) =>
      values && Object.hasOwn(values, name)
        ? String(resolveValue(values[name], namespace))
        : match,
    );
  }

  function elements(root, selector) {
    const result = Array.from(root.querySelectorAll(selector));
    if (root.matches?.(selector)) result.unshift(root);
    return result;
  }

  function apply(root = global.document) {
    global.document.documentElement.lang = language;
    const attributes = {
      "data-i18n": null,
      "data-i18n-placeholder": "placeholder",
      "data-i18n-title": "title",
      "data-i18n-aria-label": "aria-label",
      "data-i18n-alt": "alt",
    };
    for (const [marker, attribute] of Object.entries(attributes)) {
      for (const element of elements(root, `[${marker}]`)) {
        let values = {};
        try { values = JSON.parse(element.getAttribute("data-i18n-params") || "{}"); }
        catch (_) { /* Leave unresolved placeholders visible for diagnostics. */ }
        const value = translate(element.getAttribute(marker), values);
        if (attribute) element.setAttribute(attribute, value);
        else element.textContent = value;
      }
    }
    for (const select of elements(root, "[data-i18n-language]")) {
      if (!select.dataset.i18nBound) {
        select.replaceChildren(...Object.entries(languages).map(([code, label]) => {
          const option = global.document.createElement("option");
          option.value = code;
          option.textContent = code.toUpperCase();
          option.title = label;
          option.lang = code;
          return option;
        }));
        select.addEventListener("change", () => setLanguage(select.value));
        select.dataset.i18nBound = "1";
      }
      select.value = language;
      select.title = languages[language];
    }
  }

  function setLanguage(value, persist = true) {
    language = normalize(value) || "en";
    if (persist) {
      try { global.localStorage.setItem(storageKey, language); }
      catch (_) { /* The selected language still works for this page. */ }
    }
    apply();
    global.dispatchEvent(new CustomEvent("i18n:language-changed", {
      detail: { language },
    }));
    return language;
  }

  function register(namespace, translations) {
    if (Object.hasOwn(catalogs, namespace)) {
      throw new Error(`Duplicate translation catalog: ${namespace}`);
    }
    catalogs[namespace] = translations;
  }

  function use(namespace) {
    if (!Object.hasOwn(catalogs, namespace)) {
      throw new Error(`Missing translation catalog: ${namespace}`);
    }
    scope = namespace;
    global.__t = translate;
    global.getLang = () => language;
    global.setLang = setLanguage;
    global.applyTranslations = apply;
    global.document.documentElement.lang = language;
    if (global.document.readyState !== "loading") apply();
  }

  global.Bolt12I18n = Object.freeze({
    register, use, t: translate, ref, apply, setLanguage,
    getLanguage: () => language, languages, normalize,
  });
  global.document.addEventListener("DOMContentLoaded", () => { if (scope) apply(); });
  global.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) {
      setLanguage(detectLanguage(), false);
    }
  });
})(window);
