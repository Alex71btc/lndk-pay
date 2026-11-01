import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HTML = ROOT / "app/frontend/admin/index.html"


class MobileKeyboardBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = HTML.read_text(encoding="utf-8")

    def test_android_keyboard_is_dismissed_only_for_programmatic_focus(self):
        s = self.page
        self.assertIn("function dismissAndroidPaymentKeyboard()", s)
        self.assertIn("if (!isAndroidUserAgent()) return false;", s)
        self.assertIn("active.blur();", s)
        self.assertIn("if (dismissAndroidPaymentKeyboard()) return;", s)
        self.assertIn("field?.focus(options);", s)

    def test_clipboard_success_does_not_force_keyboard(self):
        a = self.page.index("function insertDetectedPaymentTarget(detected)")
        b = self.page.index("function isAndroidUserAgent()", a)
        snippet = self.page[a:b]
        self.assertIn("focusPaymentFieldAfterAutomaticInsert(payOfferInput)", snippet)
        self.assertNotIn("payOfferInput.focus();", snippet)

    def test_contacts_and_quick_repay_follow_same_rule(self):
        self.assertEqual(
            self.page.count("focusPaymentFieldAfterAutomaticInsert(payOfferInput);"),
            3,  # contacts, incoming payment intent, successful clipboard insert
        )
        self.assertIn(
            "focusPaymentFieldAfterAutomaticInsert(payAmountInput, { preventScroll: true });",
            self.page,
        )
        self.assertIn('payAmountInput.value = "";', self.page)
        self.assertIn('payerNoteInput.value = "";', self.page)

    def test_success_closes_keyboard_without_changing_success_handling(self):
        a = self.page.index("function renderSuccessOutput(")
        b = self.page.index("let payPreviewTimer", a)
        snippet = self.page[a:b]
        self.assertIn("dismissAndroidPaymentKeyboard();", snippet)
        self.assertIn("void syncTxHistory();", snippet)
        self.assertIn("paymentResultOutput.scrollIntoView", snippet)

    def test_manual_paste_fallback_still_focuses_input(self):
        a = self.page.index('function showClipboardPasteFallback(reason = "unavailable")')
        b = self.page.index("let clipboardReadInProgress", a)
        self.assertIn("payOfferInput.focus();", self.page[a:b])


if __name__ == "__main__":
    unittest.main()
