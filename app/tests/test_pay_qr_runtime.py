"""Execute the /pay QR functions and refresh handler with Node (no npm packages).

Run: python3 -m unittest discover -s app/tests -p 'test_pay_qr_runtime.py' -v
The DOM, config endpoint and QRCode drawing boundary are faked; the application
functions and event handler are extracted from the actual shipped HTML.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


PAY_HTML = Path(__file__).resolve().parents[1] / "frontend" / "admin" / "index.html"


class PayQrRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if not cls.node:
            raise RuntimeError("Node.js is required for the /pay QR regression tests")
        html = PAY_HTML.read_text(encoding="utf-8")

        def function_source(name):
            # These inline functions are top-level and use six-space indentation.
            match = re.search(
                rf"^      (?:async )?function {name}\([^\n]*\) \{{.*?^      \}}",
                html,
                re.MULTILINE | re.DOTALL,
            )
            if not match:
                raise AssertionError(f"Could not find production function {name}")
            return match.group(0)

        functions = [
            "loadDefaultAddressFromConfig",
            "readJsonOrThrow",
            "getCurrentOffer",
            "getActiveValue",
            "setCurrentOffer",
            "renderOfferQr",
        ]
        default = re.search(r'^      let DEFAULT_ADDRESS = .*?;', html, re.MULTILINE)
        refresh = re.search(
            r'      document\s*\.getElementById\("makeOfferQrBtn"\)'
            r'\s*\.addEventListener\("click", \(\) => \{.*?^        \}\);',
            html,
            re.MULTILINE | re.DOTALL,
        )
        bootstrap = re.search(
            r"<script>\s*(loadDefaultAddressFromConfig\(\);)\s*</script>", html
        )
        if not all((default, refresh, bootstrap)):
            raise AssertionError("QR default, refresh binding or page bootstrap is missing")
        cls.production = "\n".join(
            [default.group(0)]
            + [function_source(name) for name in functions]
            + [refresh.group(0)]
        )
        cls.bootstrap = bootstrap.group(1)

    def run_js(self, scenario):
        fixture = r"""
const assert = require('node:assert/strict');
const drawn = [];
const requests = [];
const statuses = [];
const timers = [];
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    value: '', textContent: '', innerHTML: '', handlers: {},
    addEventListener(event, handler) { this.handlers[event] = handler; },
  });
  return elements.get(id);
}
const document = { getElementById: element };
const window = { __t: key => key };
const offerInput = element('offerInput');
const offerPreviewBox = element('offerPreviewBox');
const offerQrBox = element('offerQrBox');
const qrModeBadge = element('qrModeBadge');
const setStatus = value => statuses.push(value);
const setTimeout = (callback, delay) => timers.push({ callback, delay });
let config = { public_bolt12_address: '  configured@merchant.test  ' };
let responseOk = true;
let fetchError = null;
let beforeResponse = async () => {};
async function fetch(url, options) {
  requests.push({ url, options });
  await beforeResponse();
  if (fetchError) throw fetchError;
  return {
    ok: responseOk, status: responseOk ? 200 : 503,
    text: async () => JSON.stringify(config),
    headers: { get: () => 'application/json' },
  };
}
function FakeQRCode(container, options) {
  assert.equal(container, offerQrBox);
  assert.equal(container.innerHTML, '', 'Refresh must clear the previous QR');
  drawn.push(options.text);
  container.innerHTML = '<canvas>drawn</canvas>';
}
FakeQRCode.CorrectLevel = { M: 0 };
let QRCode = FakeQRCode;
"""
        script = (
            fixture
            + self.production
            + "\nasync function boot() { await "
            + self.bootstrap
            + " }\n(async () => {\n"
            + scenario
            + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        )
        result = subprocess.run(
            [self.node, "-"], input=script, text=True, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_initial_page_load_draws_configured_bolt12_address(self):
        self.run_js("""
await boot();
assert.deepEqual(drawn, ['configured@merchant.test']);
assert.equal(element('defaultAddressHint').textContent, 'configured@merchant.test');
assert.equal(offerPreviewBox.textContent, 'configured@merchant.test');
assert.equal(getActiveValue(), 'configured@merchant.test');
assert.deepEqual(requests, [{url: '/api/setup/config', options: {cache: 'no-store'}}]);
""")

    def test_qr_refresh_uses_configured_address_and_replaces_previous_qr(self):
        self.run_js("""
await boot();
element('makeOfferQrBtn').handlers.click();
assert.deepEqual(drawn, ['configured@merchant.test', 'configured@merchant.test']);
assert.deepEqual(statuses, ['toast.qr_refreshed']);
assert.equal(requests.length, 1);
""")

    def test_active_offer_takes_priority_during_initialization_and_refresh(self):
        self.run_js("""
setCurrentOffer('  lno1activeoffer  ');
await boot();
element('makeOfferQrBtn').handlers.click();
assert.deepEqual(drawn, ['lno1activeoffer', 'lno1activeoffer']);
assert.equal(offerPreviewBox.textContent, 'lno1activeoffer');
assert.equal(getCurrentOffer(), 'lno1activeoffer');
assert.equal(element('defaultAddressHint').textContent, 'configured@merchant.test');
""")

    def test_offer_selected_while_config_is_loading_keeps_priority(self):
        self.run_js("""
let resolveResponse;
beforeResponse = () => new Promise(resolve => { resolveResponse = resolve; });
const loading = boot();
setCurrentOffer('lno1selectedwhileloading');
resolveResponse();
await loading;
assert.deepEqual(drawn, ['lno1selectedwhileloading']);
assert.equal(offerPreviewBox.textContent, 'lno1selectedwhileloading');
""")

    def test_clearing_offer_then_refreshing_restores_configured_address(self):
        self.run_js("""
setCurrentOffer('lno1activeoffer');
await boot();
setCurrentOffer('');
element('makeOfferQrBtn').handlers.click();
assert.deepEqual(drawn, ['lno1activeoffer', 'configured@merchant.test']);
assert.equal(offerPreviewBox.textContent, 'configured@merchant.test');
""")

    def test_config_address_aliases_are_supported(self):
        for field in ("bolt12_address", "address"):
            with self.subTest(field=field):
                self.run_js(
                    "config = " + json.dumps({field: "legacy@merchant.test"}) + ";\n"
                    "await boot();\n"
                    "assert.deepEqual(drawn, ['legacy@merchant.test']);"
                )

    def test_invalid_or_unavailable_config_preserves_existing_offer(self):
        for setup in (
            "config = {};",
            "config = { public_bolt12_address: 'invalid' };",
            "responseOk = false;",
            "fetchError = new Error('offline');",
        ):
            with self.subTest(setup=setup):
                self.run_js(setup + """
setCurrentOffer('lno1activeoffer');
await boot();
assert.equal(getActiveValue(), 'lno1activeoffer');
assert.equal(offerPreviewBox.textContent, 'lno1activeoffer');
assert.deepEqual(drawn, []);
element('makeOfferQrBtn').handlers.click();
assert.deepEqual(drawn, ['lno1activeoffer']);
""")

    def test_initialization_waits_for_qr_library_and_draws_configured_address(self):
        self.run_js("""
QRCode = undefined;
await boot();
assert.deepEqual(drawn, []);
assert.equal(timers.length, 1);
assert.equal(timers[0].delay, 100);
QRCode = FakeQRCode;
timers.shift().callback();
assert.deepEqual(drawn, ['configured@merchant.test']);
""")


if __name__ == "__main__":
    unittest.main()
