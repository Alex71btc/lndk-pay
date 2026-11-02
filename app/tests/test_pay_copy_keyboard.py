"""Exercise mobile copy/edit event ordering using the shipped /pay JavaScript.

Run with Python 3 and Node.js; no browser or npm dependencies are required.
The fixture models pointerdown's default focus before click, so a late blur or a
click-only fix cannot pass the mobile copy checks.
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path


PAY_HTML = Path(__file__).resolve().parents[1] / "frontend" / "admin" / "index.html"


class PayCopyKeyboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if not cls.node:
            raise RuntimeError("Node.js is required for the /pay copy/edit tests")
        cls.html = PAY_HTML.read_text(encoding="utf-8")

        def function_source(name):
            match = re.search(
                rf"^      (?:async )?function {name}\([^\n]*\) \{{.*?^      \}}",
                cls.html,
                re.MULTILINE | re.DOTALL,
            )
            if not match:
                raise AssertionError(f"Could not find production function {name}")
            return match.group(0)

        functions = [
            "normalizeScannedText",
            "normalizePaymentInput",
            "detectPaymentType",
            "detectClipboardPaymentTarget",
            "getClipboardPaymentTypeLabel",
            "insertDetectedPaymentTarget",
            "isAndroidUserAgent",
            "dismissAndroidPaymentKeyboard",
            "focusPaymentFieldAfterAutomaticInsert",
            "showClipboardPasteFallback",
            "isLightningAddress",
        ]
        start = cls.html.index('      payOfferInput.addEventListener("paste"')
        end = cls.html.index("      function getActiveValue()", start)
        cls.production = "\n".join(function_source(name) for name in functions)
        cls.production += "\n" + cls.html[start:end]

    def run_js(self, scenario):
        fixture = r"""
const assert = require('node:assert/strict');
const copies = [];
const statuses = [];
const elements = new Map();
const document = { activeElement: null, getElementById: element };
const navigator = { userAgent: 'Mozilla/5.0 (Linux; Android 14) SamsungBrowser/25.0' };
const window = { __t: key => key };
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    value: '', disabled: false, readOnly: false, focusCount: 0, handlers: {},
    addEventListener(type, callback) {
      (this.handlers[type] ||= []).push(callback);
    },
    focus() {
      this.focusCount += 1;
      document.activeElement = this;
    },
    blur() {
      document.activeElement = null;
      this.dispatchEvent({ type: 'blur' });
    },
    matches: () => true,
    dispatchEvent(event) {
      return Promise.all((this.handlers[event.type] || []).map(fn => fn(event)));
    },
  });
  return elements.get(id);
}
const payOfferInput = element('payOfferInput');
const copyText = async (target, message) => copies.push({ target, message });
const setStatus = (...args) => statuses.push(args);
const updatePayUiForInput = () => {};
function pointerEvent(overrides = {}) {
  return {
    type: 'pointerdown', pointerType: 'touch', button: 0, isPrimary: true,
    defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; },
    ...overrides,
  };
}
async function tap(overrides = {}) {
  const down = pointerEvent(overrides);
  await payOfferInput.dispatchEvent(down);
  // Browsers focus the input before dispatching click unless default is canceled.
  if (!down.defaultPrevented) payOfferInput.focus();
  await payOfferInput.dispatchEvent({ type: 'click', detail: 1 });
  return down;
}
"""
        script = (
            fixture + self.production + "\n(async () => {\n" + scenario
            + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        )
        result = subprocess.run(
            [self.node, "-"], input=script, text=True, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mobile_address_copy_prevents_focus_before_click(self):
        self.run_js("""
payOfferInput.value = 'lightning:alice@merchant.test';
const down = await tap();
assert.equal(down.defaultPrevented, true);
assert.equal(payOfferInput.focusCount, 0, 'Copy must not briefly open the keyboard');
assert.equal(document.activeElement, null);
assert.deepEqual(copies, [{target: 'alice@merchant.test', message: 'toast.address_copied'}]);
assert.equal(payOfferInput.value, 'lightning:alice@merchant.test');
""")

    def test_mobile_offer_and_non_android_touch_use_same_copy_rule(self):
        self.run_js("""
navigator.userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)';
payOfferInput.value = '  lno1activeoffer  ';
assert.equal((await tap()).defaultPrevented, true);
assert.equal(payOfferInput.focusCount, 0);
assert.deepEqual(copies, [{target: 'lno1activeoffer', message: 'toast.offer_copied'}]);
""")

    def test_empty_or_unrecognized_targets_still_focus_for_manual_typing(self):
        self.run_js("""
for (const value of ['', 'alice', 'lnbc1invoice']) {
  payOfferInput.blur();
  payOfferInput.value = value;
  const down = await tap();
  assert.equal(down.defaultPrevented, false);
  assert.equal(document.activeElement, payOfferInput);
}
assert.equal(payOfferInput.disabled, false);
assert.equal(payOfferInput.readOnly, false);
assert.deepEqual(copies, []);
""")

    def test_edit_button_focuses_and_cursor_taps_do_not_copy(self):
        self.run_js("""
payOfferInput.value = 'alice@merchant.test';
await element('editPayTargetBtn').dispatchEvent({type: 'click', detail: 1});
assert.equal(document.activeElement, payOfferInput);
assert.equal(payOfferInput.focusCount, 1);
const down = await tap();
assert.equal(down.defaultPrevented, false);
payOfferInput.value = 'manually-edited@merchant.test';
await payOfferInput.dispatchEvent({type: 'input'});
assert.equal(payOfferInput.value, 'manually-edited@merchant.test');
assert.equal(payOfferInput.readOnly, false);
assert.equal(payOfferInput.disabled, false);
assert.deepEqual(copies, []);
payOfferInput.blur();
assert.equal((await tap()).defaultPrevented, true);
assert.equal(copies[0].target, 'manually-edited@merchant.test');
""")

    def test_manual_paste_fallback_can_focus_and_replace_the_target(self):
        self.run_js("""
payOfferInput.value = 'alice@merchant.test';
showClipboardPasteFallback('insecure');
assert.equal(document.activeElement, payOfferInput);
assert.equal((await tap()).defaultPrevented, false);
assert.deepEqual(copies, []);
const paste = {
  type: 'paste', defaultPrevented: false,
  clipboardData: {getData: () => 'bob@merchant.test'},
  preventDefault() { this.defaultPrevented = true; },
};
await payOfferInput.dispatchEvent(paste);
assert.equal(paste.defaultPrevented, true);
assert.equal(payOfferInput.value, 'bob@merchant.test');
assert.equal(payOfferInput.readOnly, false);
assert.equal(payOfferInput.disabled, false);
""")

    def test_keyboard_focus_remains_an_editing_path(self):
        self.run_js("""
payOfferInput.value = 'alice@merchant.test';
payOfferInput.focus();
await payOfferInput.dispatchEvent({type: 'click', detail: 0});
assert.equal(document.activeElement, payOfferInput);
assert.deepEqual(copies, []);
""")

    def test_desktop_first_click_keeps_existing_focus_and_copy_behavior(self):
        self.run_js("""
navigator.userAgent = 'Mozilla/5.0 (X11; Linux x86_64)';
payOfferInput.value = 'alice@merchant.test';
assert.equal((await tap({pointerType: 'mouse'})).defaultPrevented, false);
assert.equal(document.activeElement, payOfferInput);
assert.equal(copies.length, 1);
// Subsequent clicks move the caret in the already focused field.
await tap({pointerType: 'mouse'});
assert.equal(copies.length, 1);
""")

    def test_secondary_pointers_and_buttons_are_not_intercepted(self):
        self.run_js("""
payOfferInput.value = 'alice@merchant.test';
for (const overrides of [{button: 2}, {isPrimary: false}]) {
  const down = pointerEvent(overrides);
  await payOfferInput.dispatchEvent(down);
  assert.equal(down.defaultPrevented, false);
}
assert.deepEqual(copies, []);
""")

    def test_edit_control_is_accessible_and_does_not_submit_the_payment(self):
        button = re.search(
            r'<button\s+id="editPayTargetBtn".*?</button>', self.html, re.DOTALL
        )
        self.assertIsNotNone(button)
        self.assertIn('type="button"', button.group(0))
        self.assertIn('data-i18n-title="clipboard.edit_target"', button.group(0))
        self.assertIn('data-i18n-aria-label="clipboard.edit_target"', button.group(0))


if __name__ == "__main__":
    unittest.main()
