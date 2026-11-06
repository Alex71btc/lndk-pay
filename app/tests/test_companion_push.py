import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend import companion_push


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


SUBSCRIPTION = {
    "endpoint": "https://push.example.com/webpush/random-capability",
    "p256dh": b64url(b"\x04" + b"\x11" * 64),
    "auth": b64url(b"\x22" * 16),
}


class CompanionPushTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db_path = Path(temp.name) / "companion.db"
        companion_push.init_db(self.db_path)

    def pair_device(self, *, now=100):
        pairing_token, _ = companion_push.create_pairing_token(
            self.db_path,
            now=now,
        )
        return pairing_token, companion_push.register_device(
            self.db_path,
            pairing_token=pairing_token,
            name="Pixel Test",
            now=now + 1,
            **SUBSCRIPTION,
        )

    def test_vapid_key_is_valid_and_stable(self):
        private_key = companion_push.generate_vapid_private_key()
        public_key = companion_push.vapid_public_key(private_key)

        self.assertEqual(len(base64.urlsafe_b64decode(private_key + "=")), 32)
        decoded_public = base64.urlsafe_b64decode(public_key + "=")
        self.assertEqual(len(decoded_public), 65)
        self.assertEqual(decoded_public[0], 4)
        self.assertEqual(public_key, companion_push.vapid_public_key(private_key))

    def test_pairing_token_is_hashed_one_time_and_device_token_is_revocable(self):
        pairing_token, device = self.pair_device()

        with sqlite3.connect(self.db_path) as connection:
            stored = connection.execute(
                "SELECT token_hash FROM companion_devices"
            ).fetchone()[0]
        self.assertNotEqual(stored, pairing_token)
        self.assertNotEqual(stored, device["device_token"])
        with self.assertRaises(PermissionError):
            companion_push.register_device(
                self.db_path,
                pairing_token=pairing_token,
                name="Replay",
                now=102,
                **{
                    **SUBSCRIPTION,
                    "endpoint": "https://push.example.com/webpush/other",
                },
            )
        self.assertTrue(
            companion_push.unregister_device_token(
                self.db_path,
                device["device_token"],
            )
        )
        self.assertEqual(companion_push.list_devices(self.db_path), [])

    def test_payload_uses_real_payer_note_without_private_history_fields(self):
        self.pair_device()
        item = {
            "payment_hash": "aa" * 32,
            "direction": "incoming",
            "status": "settled",
            "amount_sat": 2100,
            "method": "bolt12",
            "type": "offer",
            "memo": "technical offer description",
            "payer_note": "  First line\r\nSecond line\x00\u202e  ",
        }

        self.assertTrue(companion_push.queue_settled_payment(self.db_path, item, now=200))
        self.assertFalse(companion_push.queue_settled_payment(self.db_path, item, now=201))
        with sqlite3.connect(self.db_path) as connection:
            payload = json.loads(
                connection.execute("SELECT payload FROM companion_push_events").fetchone()[0]
            )
            delivery_count = connection.execute(
                "SELECT COUNT(*) FROM companion_push_deliveries"
            ).fetchone()[0]

        self.assertEqual(payload["amount_sat"], 2100)
        self.assertEqual(payload["method"], "bolt12")
        self.assertEqual(payload["comment"], "First line Second line")
        self.assertEqual(payload["comment_source"], "payer_note")
        self.assertNotIn("payment_hash", payload)
        self.assertNotIn("memo", payload)
        self.assertNotIn("payer_note", payload)
        self.assertEqual(delivery_count, 1)

    def test_comment_sources_distinguish_sender_text_from_invoice_description(self):
        self.assertEqual(
            companion_push._payment_comment_details(
                {
                    "method": "bolt12",
                    "payer_note": "payer note",
                    "memo": "offer description",
                }
            ),
            ("payer note", "payer_note"),
        )
        for method in ("lightning_address", "lnurl"):
            with self.subTest(method=method):
                self.assertEqual(
                    companion_push._payment_comment_details(
                        {"method": method, "memo": "LNURL comment"}
                    ),
                    ("LNURL comment", "lnurl_comment"),
                )
        self.assertEqual(
            companion_push._payment_comment_details(
                {"method": "keysend", "memo": "Keysend message"}
            ),
            ("Keysend message", "keysend_message"),
        )
        self.assertEqual(
            companion_push._payment_comment_details(
                {
                    "method": "bolt11_alias_fallback",
                    "memo": (
                        "BOLT11 alias fallback: ocean@test.alex71btc.com"
                        " · Coffee beans"
                    ),
                }
            ),
            (
                "ocean@test.alex71btc.com · Coffee beans",
                "invoice_description",
            ),
        )
        for method in ("bolt12", "bolt11", "zap"):
            with self.subTest(method=method):
                self.assertEqual(
                    companion_push._payment_comment_details(
                        {"method": method, "memo": "automatically generated memo"}
                    ),
                    ("", ""),
                )
        self.assertEqual(
            companion_push._payment_comment_details(
                {
                    "method": "bolt11_alias_fallback",
                    "memo": "unverified external invoice description",
                }
            ),
            ("", ""),
        )

    def test_comment_is_sanitized_and_bounded(self):
        raw = "  hello\n\tworld\x00\u202e " + "🚀" * 200
        comment = companion_push._sanitize_payment_comment(raw)

        self.assertTrue(comment.startswith("hello world "))
        self.assertNotIn("\x00", comment)
        self.assertNotIn("\u202e", comment)
        self.assertLessEqual(len(comment), companion_push.MAX_PUSH_COMMENT_CHARS)

    def test_reconcile_only_does_not_create_a_historical_event(self):
        self.assertFalse(
            companion_push.queue_settled_payment(
                self.db_path,
                {
                    "payment_hash": "cc" * 32,
                    "direction": "incoming",
                    "status": "settled",
                    "amount_sat": 1,
                    "method": "bolt12",
                    "type": "offer",
                    "payer_note": "late note",
                },
                now=200,
                allow_create=False,
            )
        )
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM companion_push_events"
                ).fetchone()[0],
                0,
            )

    def test_subscription_update_cannot_take_another_device_endpoint(self):
        _pairing_token, first_device = self.pair_device()
        second_subscription = {
            **SUBSCRIPTION,
            "endpoint": "https://push.example.com/webpush/second-device",
        }
        second_pairing_token, _ = companion_push.create_pairing_token(
            self.db_path,
            now=110,
        )
        second_device = companion_push.register_device(
            self.db_path,
            pairing_token=second_pairing_token,
            name="Second device",
            now=111,
            **second_subscription,
        )

        with self.assertRaises(ValueError):
            companion_push.update_device_subscription(
                self.db_path,
                device_token=second_device["device_token"],
                now=112,
                **SUBSCRIPTION,
            )

        devices = companion_push.list_devices(self.db_path)
        self.assertEqual(len(devices), 2)
        self.assertIn(first_device["id"], {device["id"] for device in devices})


class CompanionPushDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "companion.db"
        companion_push.init_db(self.db_path)
        pairing_token, _ = companion_push.create_pairing_token(self.db_path, now=100)
        companion_push.register_device(
            self.db_path,
            pairing_token=pairing_token,
            name="Pixel Test",
            now=101,
            **SUBSCRIPTION,
        )
        companion_push.queue_settled_payment(
            self.db_path,
            {
                "payment_hash": "bb" * 32,
                "direction": "incoming",
                "status": "settled",
                "amount_sat": 21,
                "method": "zap",
                "type": "zap",
            },
            now=102,
        )

    async def test_dispatch_uses_encrypted_webpush_subscription_and_marks_success(self):
        calls = []

        async def sender(**kwargs):
            calls.append(kwargs)
            return object()

        delivered = await companion_push.dispatch_due(
            self.db_path,
            vapid_private_key=companion_push.generate_vapid_private_key(),
            vapid_subject="https://pay.example.com",
            sender=sender,
            now=103,
        )

        self.assertEqual(delivered, 1)
        self.assertEqual(calls[0]["subscription_info"]["endpoint"], SUBSCRIPTION["endpoint"])
        self.assertEqual(calls[0]["headers"]["Urgency"], "high")
        with sqlite3.connect(self.db_path) as connection:
            status = connection.execute(
                "SELECT status FROM companion_push_deliveries"
            ).fetchone()[0]
        self.assertEqual(status, "delivered")

    async def test_gone_endpoint_disables_device_without_leaking_endpoint(self):
        class GoneError(RuntimeError):
            response = type("Response", (), {"status": 410})()

        async def sender(**_kwargs):
            raise GoneError("secret endpoint must not be persisted in errors")

        delivered = await companion_push.dispatch_due(
            self.db_path,
            vapid_private_key=companion_push.generate_vapid_private_key(),
            vapid_subject="https://pay.example.com",
            sender=sender,
            now=103,
        )

        self.assertEqual(delivered, 0)
        device = companion_push.list_devices(self.db_path)[0]
        self.assertFalse(device["enabled"])
        self.assertEqual(device["last_error"], "GoneError")


class CompanionPushEnrichmentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "companion.db"
        companion_push.init_db(self.db_path)
        pairing_token, _ = companion_push.create_pairing_token(self.db_path, now=100)
        companion_push.register_device(
            self.db_path,
            pairing_token=pairing_token,
            name="Pixel Test",
            now=101,
            **SUBSCRIPTION,
        )

    async def test_bolt12_note_reconciles_same_delayed_event_once(self):
        payment_hash = "dd" * 32
        initial = {
            "payment_hash": payment_hash,
            "direction": "incoming",
            "status": "settled",
            "amount_sat": 22,
            "method": "bolt11",
            "type": "invoice",
            "memo": "Public offer description",
        }
        self.assertTrue(
            companion_push.queue_settled_payment(self.db_path, initial, now=200)
        )

        calls = []

        async def sender(**kwargs):
            calls.append(kwargs)
            return object()

        delivered = await companion_push.dispatch_due(
            self.db_path,
            vapid_private_key=companion_push.generate_vapid_private_key(),
            vapid_subject="https://pay.example.com",
            sender=sender,
            now=214,
        )
        self.assertEqual(delivered, 0)
        self.assertEqual(calls, [])

        with sqlite3.connect(self.db_path) as connection:
            event_id, original_payload = connection.execute(
                "SELECT id, payload FROM companion_push_events"
            ).fetchone()
            original_due = connection.execute(
                "SELECT next_attempt_at FROM companion_push_deliveries"
            ).fetchone()[0]
        self.assertNotIn("comment", json.loads(original_payload))
        self.assertEqual(original_due, 215)

        enriched = {
            **initial,
            "method": "bolt12",
            "type": "offer",
            "payer_note": "real payer note",
        }
        self.assertTrue(
            companion_push.queue_settled_payment(
                self.db_path,
                enriched,
                now=214,
                allow_create=False,
            )
        )
        self.assertFalse(
            companion_push.queue_settled_payment(
                self.db_path,
                enriched,
                now=214,
                allow_create=False,
            )
        )

        with sqlite3.connect(self.db_path) as connection:
            reconciled_id, reconciled_payload = connection.execute(
                "SELECT id, payload FROM companion_push_events"
            ).fetchone()
            delivery_count, reconciled_due = connection.execute(
                "SELECT COUNT(*), MIN(next_attempt_at) FROM companion_push_deliveries"
            ).fetchone()
        self.assertEqual(reconciled_id, event_id)
        self.assertEqual(delivery_count, 1)
        self.assertEqual(reconciled_due, original_due)
        self.assertEqual(json.loads(reconciled_payload)["comment"], "real payer note")
        self.assertEqual(
            json.loads(reconciled_payload)["comment_source"],
            "payer_note",
        )

        delivered = await companion_push.dispatch_due(
            self.db_path,
            vapid_private_key=companion_push.generate_vapid_private_key(),
            vapid_subject="https://pay.example.com",
            sender=sender,
            now=215,
        )
        self.assertEqual(delivered, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(calls[0]["data"])["event_id"], event_id)
        self.assertEqual(
            json.loads(calls[0]["data"])["comment"],
            "real payer note",
        )

        changed_after_delivery = {**enriched, "payer_note": "too late"}
        self.assertFalse(
            companion_push.queue_settled_payment(
                self.db_path,
                changed_after_delivery,
                now=216,
                allow_create=False,
            )
        )


class PublicOnlyResolverTests(unittest.IsolatedAsyncioTestCase):
    class FakeResolver:
        def __init__(self, address):
            self.address = address
            self.closed = False

        async def resolve(self, host, port=0, family=0):
            return [
                {
                    "hostname": host,
                    "host": self.address,
                    "port": port,
                    "family": family,
                    "proto": 0,
                    "flags": 0,
                }
            ]

        async def close(self):
            self.closed = True

    async def test_private_dns_destination_is_rejected(self):
        resolver = companion_push._PublicOnlyResolver(self.FakeResolver("127.0.0.1"))

        with self.assertRaises(companion_push.UnsafePushEndpointError):
            await resolver.resolve("push.example.com", 443)

    async def test_public_dns_destination_is_allowed(self):
        resolver = companion_push._PublicOnlyResolver(self.FakeResolver("93.184.216.34"))

        records = await resolver.resolve("push.example.com", 443)

        self.assertEqual(records[0]["host"], "93.184.216.34")


if __name__ == "__main__":
    unittest.main()
