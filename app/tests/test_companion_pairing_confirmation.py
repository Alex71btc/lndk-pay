import json
import unittest
from unittest.mock import AsyncMock

from backend import companion_push


class PairingConfirmationTests(unittest.IsolatedAsyncioTestCase):
    async def test_confirmation_uses_encrypted_webpush(self):
        sender = AsyncMock()

        await companion_push.send_pairing_confirmation(
            pairing_token="test-pairing-token",
            device_token="test-device-token",
            endpoint="https://push.example.com/webpush/test",
            p256dh=companion_push._encode_base64url(
                b"\x04" + b"\x11" * 64
            ),
            auth=companion_push._encode_base64url(b"\x22" * 16),
            vapid_private_key="test-vapid-key",
            vapid_subject="mailto:test@example.com",
            sender=sender,
        )

        sender.assert_awaited_once()
        args = sender.await_args.kwargs

        payload = json.loads(args["data"])
        self.assertEqual(payload["type"], "pairing_confirmed")
        self.assertEqual(payload["pairing_token"], "test-pairing-token")
        self.assertEqual(payload["device_token"], "test-device-token")
        self.assertEqual(args["ttl"], 600)
        self.assertEqual(
            args["subscription_info"]["endpoint"],
            "https://push.example.com/webpush/test",
        )

    async def test_invalid_endpoint_is_rejected_before_sending(self):
        sender = AsyncMock()

        with self.assertRaises(ValueError):
            await companion_push.send_pairing_confirmation(
                pairing_token="test-pairing-token",
                device_token="test-device-token",
                endpoint="http://localhost/private",
                p256dh="invalid",
                auth="invalid",
                vapid_private_key="test-vapid-key",
                vapid_subject="mailto:test@example.com",
                sender=sender,
            )

        sender.assert_not_awaited()

    async def test_renewal_confirmation_contains_only_the_one_time_nonce(self):
        sender = AsyncMock()

        await companion_push.send_browser_action_confirmation(
            action_type="subscription_updated",
            action_nonce="N" * 43,
            endpoint="https://push.example.com/webpush/test",
            p256dh=companion_push._encode_base64url(
                b"\x04" + b"\x11" * 64
            ),
            auth=companion_push._encode_base64url(b"\x22" * 16),
            vapid_private_key="test-vapid-key",
            vapid_subject="mailto:test@example.com",
            sender=sender,
        )

        payload = json.loads(sender.await_args.kwargs["data"])
        self.assertEqual(payload["type"], "subscription_updated")
        self.assertEqual(payload["action_nonce"], "N" * 43)
        self.assertNotIn("device_token", payload)


if __name__ == "__main__":
    unittest.main()
