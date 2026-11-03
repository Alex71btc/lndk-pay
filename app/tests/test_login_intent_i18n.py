"""Run the shipped login/intent presentation logic without a wallet or browser.

Node supplies the JavaScript runtime. DOM, translations and browser boundaries
are faked here; the central translation runtime has its own tests.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "app"
LANGUAGES = ("en", "de", "es", "fr", "pl")


def catalog(scope):
    return {
        lang: json.loads((APP / "i18n" / scope / f"{lang}.json").read_text())
        for lang in LANGUAGES
    }


def inline_script(page, marker):
    html = (APP / "frontend" / "admin" / page).read_text()
    return next(
        script
        for script in re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
        if marker in script
    )


class LoginIntentI18nTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if not cls.node:
            raise RuntimeError("Node.js is required for login/intent i18n tests")
        cls.login = inline_script("pay-login.html", "const loginForm")
        cls.intent = inline_script("pay-intent.html", "const STORAGE_KEY")

    def run_js(self, source):
        result = subprocess.run(
            [self.node, "-"], input=source, text=True, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def login_scenario(self, scenario):
        self.run_js(
            "const translations = " + json.dumps(catalog("login")) + ";\n"
            + r"""
const assert = require('node:assert/strict');
let language = 'en';
const events = {};
const intervals = new Map();
const requests = [];
const redirects = [];
let intervalCount = 0;
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    textContent: '', value: '', disabled: false, handlers: {}, focusCount: 0,
    addEventListener(name, handler) { this.handlers[name] = handler; },
    focus() { this.focusCount++; }, select() {}, matches() { return false; },
    requestSubmit() { this.handlers.submit({preventDefault() {}}); },
  });
  return elements.get(id);
}
const document = {getElementById: element, addEventListener() {}};
const window = {
  addEventListener(name, handler) { events[name] = handler; },
  applyTranslations() {},
  __t(key, params = {}) {
    return translations[language][key].replace(/\{(\w+)\}/g, (_, name) => params[name]);
  },
  location: {origin: 'https://pay.example', search: '', assign(path) { redirects.push(path); }},
};
const setInterval = callback => { const id = ++intervalCount; intervals.set(id, callback); return id; };
const clearInterval = id => intervals.delete(id);
const setTimeout = () => 1;
const clearTimeout = () => {};
let response = {ok: false, status: 401, json: async () => ({detail: 'Invalid password'})};
async function fetch(url, options) { requests.push({url, options}); return response; }
function changeLanguage(lang) { language = lang; events['i18n:language-changed'](); }
"""
            + self.login
            + "\n(async () => {\n"
            + scenario
            + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        )

    def test_language_switch_retranslates_validation_without_submitting(self):
        self.login_scenario("""
await doLogin();
for (const lang of ['en', 'de', 'es', 'fr', 'pl']) {
  changeLanguage(lang);
  assert.equal(msgEl.textContent, translations[lang]['login.emptyPassword']);
  assert.equal(loginBtn.textContent, translations[lang]['login.login']);
  assert.equal(loginBtn.disabled, false);
}
assert.equal(requests.length, 0);
assert.equal(passwordEl.value, '');
""")

    def test_language_switch_does_not_restart_or_bypass_lockout(self):
        self.login_scenario("""
passwordEl.value = '  secret  ';
response = {ok: false, status: 429, json: async () => ({retry_after: 3})};
await doLogin();
const timer = [...intervals.values()][0];
assert.equal(intervalCount, 1);
for (const lang of ['de', 'es', 'fr', 'pl']) {
  changeLanguage(lang);
  assert.equal(loginBtn.disabled, true);
  assert.equal(loginBtn.textContent, translations[lang]['login.wait'].replace('{seconds}', '3'));
  assert.equal(msgEl.textContent, translations[lang]['login.tooManyAttempts'].replace('{seconds}', '3'));
  await doLogin();
}
assert.equal(requests.length, 1);
assert.equal(requests[0].options.body, JSON.stringify({password: '  secret  '}));
assert.equal(intervalCount, 1);
timer(); timer();
assert.equal(loginBtn.disabled, true);
assert.equal(loginBtn.textContent, translations.pl['login.wait'].replace('{seconds}', '1'));
timer();
assert.equal(loginBtn.disabled, false);
assert.equal(intervals.size, 0);
assert.equal(msgEl.textContent, '');
assert.equal(passwordEl.value, '  secret  ');
assert.deepEqual(redirects, []);
""")

    def test_language_switch_preserves_busy_state_and_one_request(self):
        self.login_scenario("""
passwordEl.value = 'secret';
let finish;
response = {ok: true, json: () => new Promise(resolve => { finish = resolve; })};
const pending = doLogin();
await Promise.resolve();
changeLanguage('fr');
assert.equal(loginBtn.textContent, translations.fr['login.loggingIn']);
assert.equal(loginBtn.disabled, true);
await doLogin();
assert.equal(requests.length, 1);
finish({});
await pending;
assert.deepEqual(redirects, ['/pay']);
""")

    def test_known_errors_translate_but_server_diagnostics_are_preserved(self):
        self.login_scenario("""
passwordEl.value = 'secret';
await doLogin();
changeLanguage('es');
assert.equal(msgEl.textContent, translations.es['login.invalidPassword']);
response = {ok: false, status: 503, json: async () => ({detail: 'custom diagnostic <check>'})};
await doLogin();
changeLanguage('pl');
assert.equal(msgEl.textContent, 'custom diagnostic <check>');
assert.equal(loginBtn.disabled, false);
""")

    def test_intent_translates_errors_without_changing_handoff(self):
        translations = catalog("intent")
        for lang in LANGUAGES:
            for mode in ("invalid", "storage_error", "valid"):
                with self.subTest(lang=lang, mode=mode):
                    self.run_js(
                        "const translations = " + json.dumps(translations[lang]) + ";\n"
                        + "const mode = " + json.dumps(mode) + ";\n"
                        + r"""
const assert = require('node:assert/strict');
const status = {dataset: {i18n: 'intent.opening'}, textContent: ''};
const document = {getElementById: id => { assert.equal(id, 'status'); return status; }};
const redirects = [];
const stored = [];
const historyCalls = [];
const window = {
  __t: key => translations[key],
  applyTranslations() { status.textContent = translations[status.dataset.i18n]; },
  location: {
    hash: mode === 'invalid' ? '#lightning=not-a-target' : '#lightning=alice%40example.com',
    pathname: '/pay-intent', replace(path) { redirects.push(path); },
  },
};
const sessionStorage = {
  removeItem(key) { stored.push(['remove', key]); },
  setItem(key, target) {
    if (mode === 'storage_error') throw Error('storage disabled');
    stored.push(['set', key, target]);
  },
};
const history = {replaceState(...args) { historyCalls.push(args); }};
"""
                        + self.intent
                        + r"""
assert.deepEqual(historyCalls, [[null, '', '/pay-intent']]);
assert.deepEqual(stored[0], ['remove', 'bolt12pay.incoming-lightning']);
if (mode === 'valid') {
  assert.deepEqual(redirects, ['/pay']);
  assert.deepEqual(stored[1], ['set', 'bolt12pay.incoming-lightning', 'alice@example.com']);
} else {
  assert.deepEqual(redirects, []);
  const key = mode === 'invalid' ? 'intent.invalid' : 'intent.handoffFailed';
  assert.equal(status.dataset.i18n, key);
  assert.equal(status.textContent, translations[key]);
}
"""
                    )

    def test_intent_handoff_page_is_self_contained(self):
        # This route forbids all external script sources, including same-origin
        # scripts, so the shared runtime and intent catalog must be inlined.
        html = (APP / "frontend/admin/pay-intent.html").read_text()
        self.assertNotRegex(html, r"<script\b[^>]*\bsrc\s*=")
        self.assertIn('Bolt12I18n.use("intent")', html)
        self.assertIn('Bolt12I18n.register("intent"', html)
        self.assertNotIn("fetch(", html)


if __name__ == "__main__":
    unittest.main()
