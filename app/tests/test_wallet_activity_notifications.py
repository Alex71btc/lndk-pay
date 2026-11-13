import ast
import re
import subprocess
import unittest
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PAY_HTML = ROOT / "app" / "frontend" / "admin" / "index.html"
COMPANION_PUSH = ROOT / "app" / "backend" / "companion_push.py"
BACKEND_APP = ROOT / "app" / "backend" / "app.py"


class WalletActivityNotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAY_HTML.read_text(encoding="utf-8")

    def function_source(self, name):
        match = re.search(
            rf"^      function {name}\(.*?^      \}}",
            self.html,
            re.S | re.M,
        )
        self.assertIsNotNone(match, name)
        return match.group(0)

    def run_node(self, source):
        result = subprocess.run(
            ["node", "-"],
            input=source,
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_settled_incoming_payments_are_deduplicated_by_hash(self):
        source = """
const assert = require('node:assert/strict');
let incomingPaymentBaselineReady = false;
const seenIncomingPaymentIds = new Set();
const shown = [];
let persisted = 0;
function persistSeenIncomingPaymentIds() { persisted++; }
function showIncomingPaymentToast(item, id) { shown.push({item, id}); }
function incomingPaymentIsRecent(item) { return item.recent !== false; }
"""
        source += self.function_source("incomingPaymentId") + "\n"
        source += self.function_source("processIncomingPaymentNotifications") + "\n"
        source += r"""
const incoming = (id, status = 'settled') => ({
  payment_hash: id, direction: 'incoming', status, amount_sat: 21,
});
const outgoing = {payment_hash: 'out', direction: 'outgoing', status: 'settled'};

assert.deepEqual(processIncomingPaymentNotifications([incoming('old'), outgoing]), []);
assert.equal(shown.length, 0, 'Existing activity is the baseline, not a new alert');

assert.deepEqual(
  processIncomingPaymentNotifications([incoming('newer'), incoming('new'), incoming('old')]),
  ['new', 'newer'],
);
assert.deepEqual(shown.map(entry => entry.id), ['new', 'newer']);
assert.deepEqual(processIncomingPaymentNotifications([incoming('newer'), incoming('new')]), []);

assert.deepEqual(processIncomingPaymentNotifications([incoming('pending', 'pending')]), []);
assert.deepEqual(processIncomingPaymentNotifications([incoming('pending')]), ['pending']);
assert.equal(shown.filter(entry => entry.id === 'pending').length, 1);
const imported = incoming('historical');
imported.recent = false;
assert.deepEqual(processIncomingPaymentNotifications([imported]), []);
assert.deepEqual(processIncomingPaymentNotifications([imported]), []);
assert.ok(persisted >= 3);
"""
        self.run_node(source)

    def test_amount_normalization_produces_digits_only(self):
        source = "const assert = require('node:assert/strict');\n"
        source += self.function_source("plainSatsValue") + "\n"
        source += r"""
assert.equal(plainSatsValue(21000), '21000');
assert.equal(plainSatsValue('00042'), '42');
assert.equal(plainSatsValue(21.9), '21');
assert.match(plainSatsValue(1234567), /^\d+$/);
assert.equal(plainSatsValue('1,000 sats'), '0');
"""
        self.run_node(source)

    def test_toast_category_reuses_localized_activity_labels(self):
        source = """
const assert = require('node:assert/strict');
const window = {__t: key => key};
"""
        source += self.function_source("incomingPaymentCategory") + "\n"
        source += """
assert.equal(incomingPaymentCategory({method: 'bolt12'}), 'history.bolt12_offer');
assert.equal(incomingPaymentCategory({method: 'offer'}), 'history.bolt12_offer');
assert.equal(incomingPaymentCategory({method: 'zap'}), 'history.nostr_zap');
assert.equal(incomingPaymentCategory({type: 'zap'}), 'history.nostr_zap');
assert.equal(incomingPaymentCategory({method: 'lightning_address'}), 'history.lightning_address');
assert.equal(incomingPaymentCategory({method: 'lnurl'}), 'history.lnurl');
assert.equal(incomingPaymentCategory({method: 'bolt11'}), 'history.bolt11_invoice');
assert.equal(incomingPaymentCategory({method: 'bolt11_alias_fallback'}), 'history.bolt11_invoice');
assert.equal(incomingPaymentCategory({method: 'keysend'}), 'history.keysend');
assert.equal(incomingPaymentCategory({method: 'unknown'}), '');
"""
        self.run_node(source)

    def test_activity_amount_is_touch_and_keyboard_accessible(self):
        amount_button = re.search(
            r'<button\s+class="txAmount".*?</button>',
            self.html,
            re.S,
        )
        self.assertIsNotNone(amount_button)
        self.assertIn('type="button"', amount_button.group(0))
        self.assertIn('aria-label=', amount_button.group(0))
        self.assertIn('history.copy_amount', amount_button.group(0))
        self.assertIn('copyText(\n              amountClipboardValue,', self.html)
        self.assertIn('window.__t("toast.amount_copied")', self.html)
        self.assertIn("event.stopPropagation()", self.html)
        self.assertIn("min-height: 44px", self.html)

    def test_payment_toast_is_viewport_fixed_safe_and_opens_exact_activity(self):
        self.assertRegex(self.html, r"\.toastWrap\s*\{\s*position:\s*fixed;")
        self.assertIn('id="paymentToastRegion"', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn('button.className = "statusBar show ok paymentToast"', self.html)
        self.assertIn("justify-items: center", self.html)
        self.assertIn("max-width: min(520px, calc(100% - 16px))", self.html)
        self.assertNotIn("background: #10241d", self.html)
        self.assertIn("categoryElement.textContent = category", self.html)
        self.assertIn("commentElement.textContent = comment", self.html)
        self.assertNotIn("commentElement.innerHTML", self.html)
        self.assertIn("rootDetails.dataset.paymentHash", self.html)
        self.assertIn("element.dataset.paymentHash === paymentHash", self.html)
        self.assertIn("paymentDetails.scrollIntoView", self.html)

    def test_browser_alert_comment_filter_reuses_private_notification_rules(self):
        tree = ast.parse(COMPANION_PUSH.read_text(encoding="utf-8"))
        names = {
            "_sanitize_payment_comment",
            "_payment_comment_details",
            "_payment_comment",
            "payment_notification_comment",
        }
        selected = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in names
        ]
        namespace = {
            "Any": Any,
            "MAX_PUSH_COMMENT_CHARS": 160,
            "unicodedata": unicodedata,
        }
        exec(
            compile(
                ast.Module(selected, type_ignores=[]),
                str(COMPANION_PUSH),
                "exec",
            ),
            namespace,
        )
        payment_notification_comment = namespace["payment_notification_comment"]

        self.assertEqual(
            payment_notification_comment(
                {"method": "bolt12", "payer_note": "  thanks\nvery much  "}
            ),
            "thanks very much",
        )
        self.assertEqual(
            payment_notification_comment(
                {"method": "bolt11", "memo": "technical invoice description"}
            ),
            "",
        )
        self.assertEqual(
            payment_notification_comment(
                {"method": "lnurl", "memo": "coffee"}
            ),
            "coffee",
        )

    def test_activity_feed_remains_authenticated_and_non_cacheable(self):
        backend = BACKEND_APP.read_text(encoding="utf-8")
        start = backend.index("def api_get_tx_history(")
        end = backend.index('@app.post("/api/admin/sync-tx-history")', start)
        endpoint = backend[start:end]
        self.assertIn("require_pay_auth(request)", endpoint)
        self.assertIn("companion_push.payment_notification_comment(item)", endpoint)
        self.assertIn("headers=_no_store_headers()", endpoint)


if __name__ == "__main__":
    unittest.main()
