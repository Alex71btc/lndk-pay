import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PAY_HTML = PROJECT_ROOT / "app" / "frontend" / "admin" / "index.html"


class PayFormInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAY_HTML.read_text(encoding="utf-8")

    def test_enter_and_button_share_the_form_submit_path(self):
        self.assertIn('<form id="payForm" class="section payHero" novalidate>', self.html)
        self.assertIn('<button id="payOfferBtn" type="submit">', self.html)
        self.assertIn('payForm?.addEventListener("submit", (event) => {', self.html)
        self.assertIn("event.preventDefault();", self.html)
        self.assertIn("void startSmartPayment();", self.html)

    def test_payment_submission_is_validated_and_single_flight(self):
        self.assertIn("function validatePaymentInputs(kind)", self.html)
        self.assertIn("!/^[1-9]\\d*$/.test(amountText)", self.html)
        self.assertIn("!Number.isSafeInteger(amountSat)", self.html)
        self.assertIn("payerNoteInput.value.length > 300", self.html)
        self.assertIn("let paymentInProgress = false;", self.html)
        self.assertIn("if (paymentInProgress)", self.html)
        self.assertIn("paymentInProgress = true;", self.html)
        self.assertIn("paymentInProgress = false;", self.html)

    def test_lightning_address_is_copied_from_pay_field(self):
        self.assertIn('id="contactPickerBtn"', self.html)
        self.assertIn("function isLightningAddress(value)", self.html)
        self.assertIn("function updatePayInputCopyState()", self.html)
        self.assertIn('classList.toggle("copyablePaymentAddress"', self.html)
        self.assertIn('payOfferInput.addEventListener("click"', self.html)
        self.assertIn('kind !== "bolt12"', self.html)
        self.assertIn('"toast.offer_copied"', self.html)
        self.assertIn('"toast.address_copied"', self.html)
        self.assertIn('"clipboard.click_target_to_copy"', self.html)
        self.assertNotIn('id="payAddressActions"', self.html)

    def test_toasts_follow_the_mobile_visual_viewport(self):
        self.assertIn('id="toastWrap"', self.html)
        self.assertIn("function updateToastViewportPosition()", self.html)
        self.assertIn("window.visualViewport?.offsetTop", self.html)
        self.assertIn('window.visualViewport?.addEventListener(\n        "scroll"', self.html)
        self.assertIn('window.visualViewport?.addEventListener(\n        "resize"', self.html)
        self.assertIn("--toast-visual-offset-top", self.html)
        self.assertIn("z-index: 2147483647", self.html)

    def test_saved_contact_status_is_shown_without_duplicate_address(self):
        self.assertIn('id="payContactStatus"', self.html)
        self.assertIn("function findContactByIdentifier(identifier)", self.html)
        self.assertIn("function refreshPayContactStatus()", self.html)
        self.assertIn('window.__t("contacts.already_saved")', self.html)
        self.assertIn("refreshPayContactStatus();", self.html)
        self.assertNotIn('id="payAddressActions"', self.html)

    def test_clipboard_button_detects_and_inserts_supported_targets(self):
        self.assertIn('id="clipboardPasteBtn"', self.html)
        self.assertIn("navigator.clipboard?.readText", self.html)
        self.assertIn("function detectClipboardPaymentTarget(raw)", self.html)
        self.assertIn('"bolt12",', self.html)
        self.assertIn('"bolt11",', self.html)
        self.assertIn('"lnurl",', self.html)
        self.assertIn('"ambiguous_address",', self.html)
        self.assertIn('"keysend",', self.html)
        self.assertIn('payOfferInput.addEventListener("paste"', self.html)
        self.assertIn("insertDetectedPaymentTarget(detected);", self.html)
        self.assertIn('"clipboard.read_unavailable"', self.html)
        self.assertIn("let clipboardReadInProgress = false;", self.html)
        self.assertNotIn("clipboardPasteBtn.disabled = true", self.html)
        self.assertNotIn('window.__t("clipboard.reading")', self.html)

    def test_clipboard_fallback_explains_insecure_android_context(self):
        self.assertIn("function isAndroidUserAgent()", self.html)
        self.assertIn('showClipboardPasteFallback("insecure")', self.html)
        self.assertIn('"clipboard.https_required"', self.html)
        self.assertIn('"clipboard.android_https_required"', self.html)

    def test_pay_scanner_is_a_compact_action_next_to_the_target(self):
        self.assertIn('class="payInputActions"', self.html)
        self.assertIn('id="scanToPayBtn"', self.html)
        self.assertIn('data-i18n-title="clipboard.scan"', self.html)
        self.assertNotIn(
            '<span data-i18n="nav.qr_pay">QR → Pay</span>',
            self.html,
        )


if __name__ == "__main__":
    unittest.main()
