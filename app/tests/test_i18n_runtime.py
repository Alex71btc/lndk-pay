"""Behavior tests for the shared browser runtime, using Node without npm packages."""

import subprocess
import unittest
from pathlib import Path


RUNTIME = Path(__file__).resolve().parents[1] / "assets" / "i18n" / "runtime.js"


class I18nRuntimeTests(unittest.TestCase):
    def run_js(self, scenario, setup=""):
        fixture = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const listeners = {};
const documentListeners = {};
let stored = null;
let storageBlocked = false;
const nodes = [];
function node(attrs = {}) {
  return {
    attrs, dataset: {}, textContent: '', value: '', children: [], handlers: {},
    getAttribute(name) { return this.attrs[name] ?? null; },
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(name, listener) { this.handlers[name] = listener; },
    replaceChildren(...children) { this.children = children; },
  };
}
const document = {
  readyState: 'loading', documentElement: {},
  createElement: () => node(),
  querySelectorAll(selector) {
    return nodes.filter(n => Object.hasOwn(n.attrs, selector.slice(1, -1)));
  },
  addEventListener(name, listener) { documentListeners[name] = listener; },
};
const window = {
  document, navigator: {languages: ['en-US']},
  localStorage: {
    getItem() { if (storageBlocked) throw new Error('blocked'); return stored; },
    setItem(key, value) { if (storageBlocked) throw new Error('blocked'); stored = value; },
  },
  addEventListener(name, listener) { (listeners[name] ||= []).push(listener); },
  dispatchEvent(event) { (listeners[event.type] || []).forEach(fn => fn(event)); },
};
const context = vm.createContext({window, CustomEvent: class {
  constructor(type, options) { this.type = type; this.detail = options.detail; }
}});
"""
        script = fixture + setup + "\n" + r"""
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
const i18n = window.Bolt12I18n;
i18n.register('test', {
  en: {hello: 'Hello {name}', fallback: 'English fallback', empty: 'English empty', unsafe: '<b>{name}</b>'},
  de: {hello: 'Hallo {name}', empty: ''}, es: {hello: 'Hola {name}'},
  fr: {hello: 'Bonjour {name}'}, pl: {hello: 'Cześć {name}'},
});
i18n.use('test');
""" + scenario
        result = subprocess.run(
            ["node", "-", str(RUNTIME)], input=script, text=True,
            capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_languages_regional_variants_and_english_fallback(self):
        self.run_js(r"""
for (const [locale, greeting] of Object.entries({
  'en-GB': 'Hello Ada', 'de-DE': 'Hallo Ada', 'es-MX': 'Hola Ada',
  'fr_CA': 'Bonjour Ada', 'pl-PL': 'Cześć Ada', 'xx': 'Hello Ada',
})) {
  window.setLang(locale);
  assert.equal(window.__t('hello', {name: 'Ada'}), greeting);
  assert.equal(window.__t('fallback'), 'English fallback');
  assert.equal(window.__t('empty'), 'English empty');
  assert.equal(window.__t('unknown.key'), 'unknown.key');
  assert.equal(window.__t('toString'), 'toString');
}
""")

    def test_browser_language_priority_and_invalid_saved_language(self):
        self.run_js("assert.equal(window.getLang(), 'pl');",
                    "window.navigator.languages = ['it-IT', 'pl-PL', 'de'];")
        self.run_js("assert.equal(window.getLang(), 'en');", "stored = 'invalid';")
        self.run_js("assert.equal(window.getLang(), 'fr');", "stored = 'fr-CA';")

    def test_storage_unavailable_does_not_prevent_initialization_or_switching(self):
        self.run_js(r"""
assert.equal(window.getLang(), 'de');
window.setLang('es');
assert.equal(window.__t('hello', {name: 'Ada'}), 'Hola Ada');
""", "storageBlocked = true; window.navigator.languages = ['de'];")

    def test_repeated_placeholders_and_unknown_placeholder_are_preserved(self):
        self.run_js(r"""
i18n.register('params', {en: {count: '{count}/{count} {missing}'}});
i18n.use('params');
assert.equal(window.__t('count', {count: 0}), '0/0 {missing}');
assert.equal(window.__t('count', {count: '$&'}), '$&/$& {missing}');
""")

    def test_nested_translation_parameters_follow_language_changes(self):
        self.run_js(r"""
i18n.register('nested', {
  en: {outer: 'Problem: {detail}', detail: 'Unexpected response (HTTP {status})'},
  de: {outer: 'Problem: {detail}', detail: 'Unerwartete Antwort (HTTP {status})'},
});
i18n.use('nested');
const params = {detail: i18n.ref('detail', {status: 404})};
const status = node({'data-i18n': 'outer', 'data-i18n-params': JSON.stringify(params)});
nodes.push(status);
window.applyTranslations();
assert.equal(status.textContent, 'Problem: Unexpected response (HTTP 404)');
window.setLang('de');
assert.equal(status.textContent, 'Problem: Unerwartete Antwort (HTTP 404)');
""")

    def test_dom_translation_uses_text_and_preserves_editable_values(self):
        self.run_js(r"""
const title = node({'data-i18n': 'unsafe', 'data-i18n-params': '{"name":"<img src=x>"}'});
const input = node({'data-i18n-placeholder': 'hello', 'data-i18n-params': '{"name":"Ada"}'});
input.value = 'alice@example.com';
const button = node({'data-i18n-title': 'fallback', 'data-i18n-aria-label': 'fallback'});
nodes.push(title, input, button);
window.setLang('de');
assert.equal(title.textContent, '<b><img src=x></b>');
assert.equal(title.innerHTML, undefined);
assert.equal(input.attrs.placeholder, 'Hallo Ada');
assert.equal(input.value, 'alice@example.com');
assert.equal(button.attrs['aria-label'], 'English fallback');
assert.equal(document.documentElement.lang, 'de');
""")

    def test_selector_and_language_event_switch_all_five_languages(self):
        self.run_js(r"""
const select = node({'data-i18n-language': ''});
nodes.push(select);
const changes = [];
window.addEventListener('i18n:language-changed', event => changes.push(event.detail.language));
documentListeners.DOMContentLoaded();
assert.equal(select.children.length, 5);
for (const code of ['de', 'es', 'fr', 'pl', 'en']) {
  select.value = code;
  select.handlers.change();
  assert.equal(window.getLang(), code);
  assert.equal(stored, code);
}
assert.deepEqual(changes, ['de', 'es', 'fr', 'pl', 'en']);
assert.equal(select.children.length, 5);
""")

    def test_storage_events_sync_language_across_pages(self):
        self.run_js(r"""
stored = 'fr';
window.dispatchEvent({type: 'storage', key: 'app_lang'});
assert.equal(window.getLang(), 'fr');
stored = null;
window.dispatchEvent({type: 'storage', key: null});
assert.equal(window.getLang(), 'en');
""")

    def test_duplicate_scopes_and_missing_scopes_fail_explicitly(self):
        self.run_js(r"""
assert.throws(() => i18n.register('test', {}), /Duplicate translation catalog/);
assert.throws(() => i18n.use('unknown'), /Missing translation catalog/);
""")


if __name__ == "__main__":
    unittest.main()
