import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PayLoginLayoutTests(unittest.TestCase):
    def test_login_card_stays_inside_narrow_viewports(self):
        html = (
            PROJECT_ROOT / "app" / "frontend" / "admin" / "pay-login.html"
        ).read_text(encoding="utf-8")

        self.assertIn("*, *::before, *::after", html)
        self.assertIn("box-sizing: border-box", html)
        self.assertIn("min-height: 100dvh", html)
        self.assertIn("width: min(420px, 100%)", html)
        self.assertNotIn("width: min(420px, calc(100vw - 32px))", html)

    def test_payment_method_dialog_has_mobile_single_column_layout(self):
        html = (
            PROJECT_ROOT / "app" / "frontend" / "admin" / "index.html"
        ).read_text(encoding="utf-8")

        self.assertIn('id="paymentMethodModal"', html)
        self.assertIn('id="chooseBolt12MethodBtn"', html)
        self.assertIn('id="chooseLnurlMethodBtn"', html)
        self.assertIn('id="payPreviewBolt12Availability"', html)
        self.assertIn("BOLT12 verfügbar", html)
        self.assertIn(".paymentMethodChoices", html)
        self.assertIn("grid-template-columns: 1fr", html)
        self.assertIn("height: 100dvh", html)
        self.assertIn("max-height: calc(100dvh - 20px)", html)


if __name__ == "__main__":
    unittest.main()
