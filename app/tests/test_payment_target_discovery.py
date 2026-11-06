import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

import backend.app as app_module


class PaymentTargetDiscoveryTests(unittest.TestCase):
    def discovery(self, *, privacy=False):
        config = {
            "aliases": {
                "alice": {
                    "description": "Tips for Alice",
                    "amount_sat": None,
                    "last_offer": "lno1reusableoffer",
                }
            }
        }
        with (
            patch.object(app_module, "load_config", return_value=config),
            patch.object(app_module, "get_lnurl_base_domain", return_value="example.com"),
            patch.object(app_module, "get_lnurl_base_url", return_value="https://pay.example.com"),
            patch.object(app_module, "get_bip353_base_domain", return_value="example.com"),
            patch.object(app_module, "privacy_mode_enabled", return_value=privacy),
            patch.object(
                app_module,
                "_get_nostr_identity_for_name",
                return_value={
                    "nostr_pubkey": "22" * 32,
                    "zap_enabled": True,
                },
            ),
            patch.object(app_module, "_nostr_server_pubkey_hex", return_value="33" * 32),
        ):
            return app_module._payment_target_discovery("Alice")

    def test_versioned_schema_describes_offer_address_lnurl_and_capabilities(self):
        payload = self.discovery()

        self.assertEqual(payload["schema"], "bolt12-pay/payment-target-discovery")
        self.assertEqual(payload["version"], 1)
        self.assertNotIn("server_version", payload)
        self.assertEqual(payload["identifier"], "alice@example.com")
        methods = {item["type"]: item for item in payload["methods"]}
        self.assertEqual(
            set(methods),
            {"bolt12_offer", "lightning_address", "lnurl_pay"},
        )
        self.assertEqual(methods["bolt12_offer"]["offer"], "lno1reusableoffer")
        self.assertEqual(methods["bolt12_offer"]["amount"]["min_msat"], 1000)
        self.assertEqual(methods["lightning_address"]["resolves_to"], "lnurl_pay")
        self.assertEqual(methods["lnurl_pay"]["comment"]["max_chars"], 120)
        self.assertTrue(methods["lnurl_pay"]["zap"]["supported"])
        self.assertEqual(payload["qr"]["primary"]["type"], "bolt12_offer")
        self.assertEqual(
            payload["qr"]["bolt11_fallback"]["type"],
            "bolt11_invoice",
        )
        self.assertTrue(payload["qr"]["bolt11_fallback"]["generated_on_demand"])

    def test_privacy_mode_omits_lnurl_methods_without_hiding_bolt12(self):
        payload = self.discovery(privacy=True)

        self.assertEqual(
            [method["type"] for method in payload["methods"]],
            ["bolt12_offer"],
        )
        self.assertIsNone(payload["addresses"]["lightning"])
        self.assertIsNone(payload["qr"]["bolt11_fallback"])

    def test_qr_classifier_distinguishes_offer_invoice_and_address(self):
        cases = {
            "lno1offer": "bolt12_offer",
            "LIGHTNING:lni1invoice": "bolt12_invoice",
            "lnr1request": "bolt12_invoice_request",
            "lightning:lnbc210n1invoice?amount=1": "bolt11_invoice",
            "LNURL1PAYLOAD": "lnurl",
            "alice@example.com": "payment_address",
            "not a payment": "unknown",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(app_module._classify_qr_value(value), expected)


class QrResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_qr_response_exposes_machine_readable_type(self):
        response = await app_module.qr_code("lno1offer")

        self.assertEqual(response.media_type, "image/png")
        self.assertEqual(response.headers["x-bolt12-pay-qr-type"], "bolt12_offer")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertTrue(response.body.startswith(b"\x89PNG"))


class PublicFallbackRateLimitTests(unittest.TestCase):
    def setUp(self):
        app_module._PUBLIC_ALIAS_INVOICE_RATE_LIMITS.clear()
        self.addCleanup(app_module._PUBLIC_ALIAS_INVOICE_RATE_LIMITS.clear)

    @staticmethod
    def request(forwarded_ip):
        return SimpleNamespace(
            headers={"x-forwarded-for": forwarded_ip},
            client=SimpleNamespace(host="127.0.0.1"),
        )

    def test_global_alias_limit_cannot_be_bypassed_with_forwarded_ips(self):
        with (
            patch.object(app_module, "PUBLIC_ALIAS_INVOICE_RATE_LIMIT_MAX_REQUESTS", 3),
            patch.object(
                app_module,
                "PUBLIC_ALIAS_INVOICE_GLOBAL_RATE_LIMIT_MAX_REQUESTS",
                2,
            ),
        ):
            app_module._check_public_alias_invoice_rate_limit(
                self.request("198.51.100.1"),
                "alice",
            )
            app_module._check_public_alias_invoice_rate_limit(
                self.request("198.51.100.2"),
                "alice",
            )
            with self.assertRaises(HTTPException) as raised:
                app_module._check_public_alias_invoice_rate_limit(
                    self.request("198.51.100.3"),
                    "alice",
                )

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(
            len(app_module._PUBLIC_ALIAS_INVOICE_RATE_LIMITS["alias:alice"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
