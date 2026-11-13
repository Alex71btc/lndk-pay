import json
import unittest
from unittest.mock import patch

import backend.app as app_module


class TxHistoryPaymentAlertApiTests(unittest.TestCase):
    def test_feed_is_authenticated_private_and_exposes_only_alert_safe_comments(self):
        request = object()
        items = [
            {
                "payment_hash": "11" * 32,
                "direction": "incoming",
                "status": "settled",
                "method": "bolt12",
                "payer_note": "  thank you\nfriend  ",
                "memo": "technical invoice memo",
            },
            {
                "payment_hash": "22" * 32,
                "direction": "incoming",
                "status": "settled",
                "method": "bolt11",
                "payer_note": None,
                "memo": "technical invoice memo",
            },
        ]

        with (
            patch.object(app_module, "require_pay_auth") as require_auth,
            patch.object(app_module, "list_tx_history", return_value=items),
        ):
            response = app_module.api_get_tx_history(
                request,
                limit=50,
                offset=0,
                q="",
            )

        require_auth.assert_called_once_with(request)
        self.assertTrue(response.headers["cache-control"].startswith("no-store"))
        payload = json.loads(response.body)
        self.assertEqual(payload["items"][0]["notification_comment"], "thank you friend")
        self.assertNotIn("notification_comment", payload["items"][1])


if __name__ == "__main__":
    unittest.main()
