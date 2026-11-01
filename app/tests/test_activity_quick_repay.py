import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "app/frontend/admin/index.html"
VERSION = ROOT / "app/VERSION"


class ActivityQuickRepayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAGE.read_text(encoding="utf-8")

    def test_version(self):
        self.assertEqual(VERSION.read_text().strip(), "0.3.19")

    def test_success_opens_and_syncs_activity(self):
        start = self.html.index("function renderSuccessOutput(")
        stop = self.html.index("let payPreviewTimer", start)
        fragment = self.html[start:stop]
        self.assertIn('getElementById("txHistorySection")', fragment)
        self.assertIn("if (activity) activity.open = true", fragment)
        self.assertIn("void syncTxHistory()", fragment)
        self.assertIn("paymentResultOutput.scrollIntoView", fragment)

    def test_only_reusable_outgoing_targets(self):
        self.assertIn('item.direction === "outgoing"', self.html)
        self.assertIn('detectClipboardPaymentTarget(repeatTargetCandidate)', self.html)
        self.assertIn('detectedRepeatTarget?.kind !== "bolt11"', self.html)
        self.assertIn('repeatTarget?.kind === "keysend"', self.html)
        self.assertIn('class="txRepeatTarget" type="button"', self.html)
        self.assertIn('escapeContactHtml(visibleTarget)', self.html)

    def test_repay_is_explicit_and_clears_previous_payment(self):
        start = self.html.index('const repeatButton = div.querySelector(".txRepeatTarget")')
        end = self.html.index('const contactElement = div.querySelector', start)
        fragment = self.html[start:end]
        self.assertIn('event.stopPropagation()', fragment)
        self.assertIn('if (paymentInProgress)', fragment)
        self.assertIn('payOfferInput.value = repeatTarget.target', fragment)
        self.assertIn('payAmountInput.value = ""', fragment)
        self.assertIn('payerNoteInput.value = ""', fragment)
        self.assertIn('payOfferInput.dispatchEvent(new Event("input"', fragment)
        self.assertNotIn('startSmartPayment(', fragment)
        self.assertNotIn('payForm.requestSubmit(', fragment)

    def test_translations_exist(self):
        self.assertEqual(self.html.count('"history.reuse_target":'), 2)
        self.assertEqual(self.html.count('"toast.activity_target_to_pay":'), 2)


if __name__ == "__main__":
    unittest.main()
