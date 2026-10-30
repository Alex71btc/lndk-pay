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

    def test_lightning_address_has_copy_and_contact_actions(self):
        self.assertIn('id="payAddressActions"', self.html)
        self.assertIn('id="copyPayAddressBtn"', self.html)
        self.assertIn('id="savePayAddressBtn"', self.html)
        self.assertIn("function isLightningAddress(value)", self.html)
        self.assertIn("refreshPayAddressActions();", self.html)
        self.assertIn(
            'copyText(address, window.__t("toast.address_copied"))',
            self.html,
        )
        self.assertIn("openSaveContactModal();", self.html)


if __name__ == "__main__":
    unittest.main()
