import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import backend.app as app_module


class PayAddressResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reports_both_bolt12_and_lnurl(self):
        lnurl_metadata = {
            "callback": "https://example.com/lnurl/callback",
            "minSendable": 1_000,
            "maxSendable": 2_000_000,
            "commentAllowed": 120,
            "metadata": '[["text/plain","Phoenix address"]]',
        }

        with (
            patch.object(
                app_module,
                "_resolve_bip353_address",
                return_value="lno1testoffer",
            ),
            patch.object(
                app_module,
                "_fetch_lnurl_metadata_from_url",
                new=AsyncMock(return_value=lnurl_metadata),
            ),
        ):
            result = await app_module._resolve_pay_address_methods(
                "alice@example.com"
            )

        self.assertEqual(result["available_methods"], ["bolt12", "lnurl"])
        self.assertEqual(result["bolt12"]["resolved_offer"], "lno1testoffer")
        self.assertEqual(result["lnurl"]["min_sat"], 1)
        self.assertEqual(result["lnurl"]["max_sat"], 2_000)
        self.assertEqual(result["lnurl"]["description"], "Phoenix address")

    async def test_reports_lnurl_when_bip353_is_missing(self):
        with (
            patch.object(
                app_module,
                "_resolve_bip353_address",
                side_effect=HTTPException(status_code=404, detail="no record"),
            ),
            patch.object(
                app_module,
                "_fetch_lnurl_metadata_from_url",
                new=AsyncMock(
                    return_value={
                        "callback": "https://example.com/lnurl/callback",
                    }
                ),
            ),
        ):
            result = await app_module._resolve_pay_address_methods(
                "alice@example.com"
            )

        self.assertEqual(result["available_methods"], ["lnurl"])
        self.assertFalse(result["bolt12"]["available"])
        self.assertEqual(result["bolt12"]["error"], "no record")

    async def test_rejects_lnurl_metadata_without_callback(self):
        with (
            patch.object(
                app_module,
                "_resolve_bip353_address",
                return_value="lno1testoffer",
            ),
            patch.object(
                app_module,
                "_fetch_lnurl_metadata_from_url",
                new=AsyncMock(return_value={"minSendable": 1_000}),
            ),
        ):
            result = await app_module._resolve_pay_address_methods(
                "alice@example.com"
            )

        self.assertEqual(result["available_methods"], ["bolt12"])
        self.assertFalse(result["lnurl"]["available"])
        self.assertIn("missing callback", result["lnurl"]["error"])

    async def test_forced_lnurl_skips_bolt12_resolution(self):
        expected = app_module.PayOfferResponse(
            resolved_offer="alice@example.com",
            raw_output='{"mode":"lnurl"}',
        )
        payload = app_module.PayAddressRequest(
            target="alice@example.com",
            amount_sat=21,
            payment_method="lnurl",
        )

        with (
            patch.object(app_module, "require_pay_auth"),
            patch.object(app_module, "_require_csrf"),
            patch.object(
                app_module,
                "_pay_address_via_lnurl",
                new=AsyncMock(return_value=expected),
            ) as pay_lnurl,
            patch.object(app_module, "_normalize_offer_or_hrn") as resolve_bolt12,
        ):
            result = await app_module.pay_address(payload, object())

        self.assertEqual(result, expected)
        pay_lnurl.assert_awaited_once_with(payload)
        resolve_bolt12.assert_not_called()

    async def test_forced_bolt12_never_falls_back_to_lnurl(self):
        payload = app_module.PayAddressRequest(
            target="alice@example.com",
            amount_sat=21,
            payment_method="bolt12",
        )

        with (
            patch.object(app_module, "require_pay_auth"),
            patch.object(app_module, "_require_csrf"),
            patch.object(
                app_module,
                "_normalize_offer_or_hrn",
                side_effect=HTTPException(status_code=404, detail="no record"),
            ),
            patch.object(
                app_module,
                "_pay_address_via_lnurl",
                new=AsyncMock(),
            ) as pay_lnurl,
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.pay_address(payload, object())

        self.assertEqual(raised.exception.status_code, 404)
        pay_lnurl.assert_not_awaited()

    async def test_legacy_auto_mode_keeps_lnurl_fallback(self):
        expected = app_module.PayOfferResponse(
            resolved_offer="alice@example.com",
            raw_output='{"mode":"lnurl"}',
        )
        payload = app_module.PayAddressRequest(
            target="alice@example.com",
            amount_sat=21,
        )

        with (
            patch.object(app_module, "require_pay_auth"),
            patch.object(app_module, "_require_csrf"),
            patch.object(
                app_module,
                "_normalize_offer_or_hrn",
                side_effect=HTTPException(status_code=404, detail="no record"),
            ),
            patch.object(
                app_module,
                "_pay_address_via_lnurl",
                new=AsyncMock(return_value=expected),
            ) as pay_lnurl,
        ):
            result = await app_module.pay_address(payload, object())

        self.assertEqual(result, expected)
        pay_lnurl.assert_awaited_once_with(payload)


if __name__ == "__main__":
    unittest.main()
