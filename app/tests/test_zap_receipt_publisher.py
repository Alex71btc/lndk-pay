import asyncio
import contextlib
import copy
import json
import time
import unittest
from unittest.mock import AsyncMock, patch

import backend.app as app_module


class FakeRelayConnection:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def send(self, message):
        self.sent.append(json.loads(message))

    async def recv(self):
        return self.messages.pop(0)


def pending_zap(*, relays):
    return {
        "created_at": int(time.time()),
        "recipient_pubkey_hex": "11" * 32,
        "payer_pubkey_hex": "22" * 32,
        "amount_msat": 21_000,
        "payment_request": "lnbc-test-invoice",
        "relays": relays,
        "zap_request_event": {"pubkey": "22" * 32, "tags": []},
        "notification_published": True,
        "published": False,
    }


def signed_zap_request(*, recipient_pubkey, amount_msat=21_000):
    private_key = app_module.coincurve.PrivateKey(bytes.fromhex("33" * 32))
    pubkey = private_key.public_key_xonly.format().hex()
    event = {
        "pubkey": pubkey,
        "created_at": 1_700_000_000,
        "kind": 9734,
        "tags": [
            ["relays", "wss://relay.example"],
            ["amount", str(amount_msat)],
            ["p", recipient_pubkey],
        ],
        "content": "Zap ⚡",
    }
    event["id"] = app_module._nostr_event_id_hex(event)
    event["sig"] = private_key.sign_schnorr(
        bytes.fromhex(event["id"]),
        aux_randomness=b"\x00" * 32,
    ).hex()
    return event


class ZapProtocolTests(unittest.TestCase):
    def test_lnurl_metadata_advertises_receipt_signer(self):
        signer_pubkey = "aa" * 32
        identity_pubkey = "bb" * 32
        alias = {
            "username": "test",
            "identifier": "test@example.com",
            "description": "Test",
            "fixed_amount_sat": None,
        }

        with (
            patch.object(app_module, "_resolve_lnurl_alias", return_value=alias),
            patch.object(
                app_module,
                "_get_nostr_pubkey_hex_for_name",
                return_value=identity_pubkey,
            ),
            patch.object(
                app_module,
                "_nostr_server_pubkey_hex",
                return_value=signer_pubkey,
            ),
            patch.object(
                app_module,
                "_lnurl_callback_url",
                return_value="https://example.com/callback",
            ),
            patch.object(
                app_module,
                "_lnurl_metadata_json",
                return_value="[]",
            ),
        ):
            response = app_module.lnurl_pay_metadata("test")

        self.assertTrue(response.allowsNostr)
        self.assertEqual(response.nostrPubkey, signer_pubkey)
        self.assertNotEqual(response.nostrPubkey, identity_pubkey)

    def test_advertised_signer_matches_signed_receipt(self):
        server_privkey = "55" * 32
        alias = {
            "username": "test",
            "identifier": "test@example.com",
            "description": "Test",
            "fixed_amount_sat": None,
        }
        item = pending_zap(relays=["wss://relay.example"])

        with (
            patch.object(app_module, "_get_secret", return_value=server_privkey),
            patch.object(app_module, "_resolve_lnurl_alias", return_value=alias),
            patch.object(
                app_module,
                "_lnurl_callback_url",
                return_value="https://example.com/callback",
            ),
            patch.object(
                app_module,
                "_lnurl_metadata_json",
                return_value="[]",
            ),
        ):
            metadata = app_module.lnurl_pay_metadata("test")
            receipt = app_module._build_zap_receipt_event(
                item,
                {"settle_date": "1700000001"},
            )

        self.assertEqual(metadata.nostrPubkey, receipt["pubkey"])

    def test_zap_request_requires_a_valid_signature(self):
        recipient_pubkey = "11" * 32
        event = signed_zap_request(recipient_pubkey=recipient_pubkey)
        raw_event = json.dumps(event, ensure_ascii=False, indent=2)

        parsed = app_module._parse_zap_request(
            raw_event,
            expected_pubkey_hex=recipient_pubkey,
            amount_msat=21_000,
        )
        self.assertEqual(parsed["id"], event["id"])

        event["content"] = "tampered"
        with self.assertRaises(app_module.HTTPException) as raised:
            app_module._parse_zap_request(
                json.dumps(event, ensure_ascii=False),
                expected_pubkey_hex=recipient_pubkey,
                amount_msat=21_000,
            )
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "Invalid zap request signature")

    def test_receipt_preserves_exact_description_and_target_kind(self):
        raw_request = '{\n  "content": "Zap ⚡", "kind": 9734\n}'
        item = pending_zap(relays=["wss://relay.example"])
        item["zap_request_raw"] = raw_request
        item["zap_request_event"]["tags"] = [
            ["e", "44" * 32],
            ["k", "1"],
        ]

        with patch.object(
            app_module,
            "_sign_nostr_event",
            side_effect=lambda event: event,
        ):
            receipt = app_module._build_zap_receipt_event(
                item,
                {"settle_date": "1700000001"},
            )

        self.assertIn(["description", raw_request], receipt["tags"])
        self.assertIn(["k", "1"], receipt["tags"])

    def test_receipt_event_id_uses_unescaped_unicode(self):
        event = {
            "pubkey": "aa" * 32,
            "created_at": 1_700_000_000,
            "kind": 9735,
            "tags": [["description", "Zap ⚡"]],
            "content": "",
        }
        expected_payload = json.dumps(
            [
                0,
                event["pubkey"],
                event["created_at"],
                event["kind"],
                event["tags"],
                event["content"],
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        expected_id = app_module.hashlib.sha256(
            expected_payload.encode("utf-8")
        ).hexdigest()

        self.assertEqual(app_module._nostr_event_id_hex(event), expected_id)


class ZapRelayPublishTests(unittest.IsolatedAsyncioTestCase):
    async def test_publish_waits_for_matching_relay_acceptance(self):
        event = {"id": "event-id", "kind": 9735}
        connection = FakeRelayConnection(
            [
                json.dumps(["NOTICE", "processing"]),
                json.dumps(["OK", "event-id", True, "saved"]),
            ]
        )

        with patch.object(
            app_module.websockets,
            "connect",
            return_value=connection,
        ):
            result = await app_module._publish_nostr_event_to_relay(
                "wss://relay.example",
                event,
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["accepted"])
        self.assertEqual(result["message"], "saved")
        self.assertEqual(connection.sent, [["EVENT", event]])

    async def test_relay_rejection_is_not_reported_as_published(self):
        event = {"id": "event-id", "kind": 9735}
        connection = FakeRelayConnection(
            [json.dumps(["OK", "event-id", False, "auth-required"])]
        )

        with patch.object(
            app_module.websockets,
            "connect",
            return_value=connection,
        ):
            result = await app_module._publish_nostr_event_to_relay(
                "wss://relay.example",
                event,
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["message"], "auth-required")


class ZapQueueTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        app_module.NOSTR_ZAP_NEXT_ATTEMPT_MONOTONIC.clear()

    async def test_partial_relay_success_completes_receipt_and_preserves_new_zap(self):
        first_relay = "wss://one.example"
        second_relay = "wss://two.example"
        store = {
            "pending_zaps": {
                "old-payment-hash": pending_zap(
                    relays=[first_relay, second_relay]
                )
            }
        }

        def load_config():
            return copy.deepcopy(store)

        def save_config(config):
            store.clear()
            store.update(copy.deepcopy(config))

        async def first_lookup(_payment_hash):
            store["pending_zaps"]["new-payment-hash"] = {
                "published": True,
            }
            return {
                "settled": True,
                "settle_date": "1700000000",
                "r_preimage": "preimage",
            }

        def sign_event(event):
            return {
                **event,
                "pubkey": "33" * 32,
                "id": "stable-receipt-id",
                "sig": "44" * 64,
            }

        publish = AsyncMock(
            return_value=[
                {"relay": first_relay, "ok": True, "accepted": True},
                {"relay": second_relay, "ok": False, "accepted": False},
            ]
        )

        with (
            patch.object(app_module, "load_config", side_effect=load_config),
            patch.object(app_module, "save_config", side_effect=save_config),
            patch.object(
                app_module,
                "_lookup_invoice",
                new=AsyncMock(side_effect=first_lookup),
            ),
            patch.object(app_module, "_sign_nostr_event", side_effect=sign_event) as sign,
            patch.object(app_module, "_publish_nostr_event", new=publish),
        ):
            await app_module._process_pending_zaps_once()

            self.assertIn("new-payment-hash", store["pending_zaps"])
            saved = store["pending_zaps"]["old-payment-hash"]
            self.assertTrue(saved["receipt_published"])
            self.assertTrue(saved["published"])
            self.assertEqual(saved["receipt_event"]["id"], "stable-receipt-id")
            self.assertEqual(publish.await_args.args[0], [first_relay, second_relay])
            self.assertNotIn(
                "old-payment-hash",
                app_module.NOSTR_ZAP_NEXT_ATTEMPT_MONOTONIC,
            )
        self.assertEqual(publish.await_count, 1)
        self.assertEqual(sign.call_count, 1)

    async def test_all_relay_failures_reuse_receipt_event_on_retry(self):
        first_relay = "wss://one.example"
        second_relay = "wss://two.example"
        store = {
            "pending_zaps": {
                "payment-hash": pending_zap(relays=[first_relay, second_relay])
            }
        }

        def load_config():
            return copy.deepcopy(store)

        def save_config(config):
            store.clear()
            store.update(copy.deepcopy(config))

        def sign_event(event):
            return {
                **event,
                "pubkey": "33" * 32,
                "id": "stable-receipt-id",
                "sig": "44" * 64,
            }

        publish = AsyncMock(
            side_effect=[
                [
                    {"relay": first_relay, "ok": False, "accepted": False},
                    {"relay": second_relay, "ok": False, "accepted": False},
                ],
                [
                    {"relay": first_relay, "ok": True, "accepted": True},
                    {"relay": second_relay, "ok": False, "accepted": False},
                ],
            ]
        )

        with (
            patch.object(app_module, "load_config", side_effect=load_config),
            patch.object(app_module, "save_config", side_effect=save_config),
            patch.object(
                app_module,
                "_lookup_invoice",
                new=AsyncMock(
                    return_value={
                        "settled": True,
                        "settle_date": "1700000000",
                    }
                ),
            ),
            patch.object(app_module, "_sign_nostr_event", side_effect=sign_event) as sign,
            patch.object(app_module, "_publish_nostr_event", new=publish),
        ):
            await app_module._process_pending_zaps_once()
            saved = store["pending_zaps"]["payment-hash"]
            self.assertFalse(saved["receipt_published"])
            self.assertIn(
                "payment-hash",
                app_module.NOSTR_ZAP_NEXT_ATTEMPT_MONOTONIC,
            )

            app_module.NOSTR_ZAP_NEXT_ATTEMPT_MONOTONIC.pop("payment-hash", None)
            await app_module._process_pending_zaps_once()

        saved = store["pending_zaps"]["payment-hash"]
        self.assertTrue(saved["receipt_published"])
        self.assertTrue(saved["published"])
        self.assertEqual(publish.await_count, 2)
        self.assertEqual(publish.await_args_list[0].args[0], [first_relay, second_relay])
        self.assertEqual(publish.await_args_list[1].args[0], [first_relay, second_relay])
        self.assertEqual(sign.call_count, 1)

    async def test_one_broken_item_does_not_block_the_next_zap(self):
        relay = "wss://relay.example"
        store = {
            "pending_zaps": {
                "broken-hash": pending_zap(relays=[relay]),
                "working-hash": pending_zap(relays=[relay]),
            }
        }

        def load_config():
            return copy.deepcopy(store)

        def save_config(config):
            store.clear()
            store.update(copy.deepcopy(config))

        async def lookup(payment_hash):
            if payment_hash == "broken-hash":
                raise RuntimeError("temporary LND error")
            return {"settled": True, "settle_date": "1700000000"}

        def sign_event(event):
            return {
                **event,
                "pubkey": "33" * 32,
                "id": "working-receipt-id",
                "sig": "44" * 64,
            }

        with (
            patch.object(app_module, "load_config", side_effect=load_config),
            patch.object(app_module, "save_config", side_effect=save_config),
            patch.object(
                app_module,
                "_lookup_invoice",
                new=AsyncMock(side_effect=lookup),
            ),
            patch.object(app_module, "_sign_nostr_event", side_effect=sign_event),
            patch.object(
                app_module,
                "_publish_nostr_event",
                new=AsyncMock(
                    return_value=[
                        {"relay": relay, "ok": True, "accepted": True}
                    ]
                ),
            ),
        ):
            await app_module._process_pending_zaps_once()

        self.assertIn("temporary LND error", store["pending_zaps"]["broken-hash"]["last_error"])
        self.assertTrue(store["pending_zaps"]["working-hash"]["receipt_published"])

    async def test_expired_unpaid_zap_is_finished_without_querying_lnd(self):
        old_item = pending_zap(relays=["wss://relay.example"])
        old_item["created_at"] = int(time.time()) - 7200
        old_item["expires_at"] = int(time.time()) - 600
        store = {"pending_zaps": {"expired-hash": old_item}}

        def load_config():
            return copy.deepcopy(store)

        def save_config(config):
            store.clear()
            store.update(copy.deepcopy(config))

        lookup = AsyncMock()
        with (
            patch.object(app_module, "load_config", side_effect=load_config),
            patch.object(app_module, "save_config", side_effect=save_config),
            patch.object(app_module, "_lookup_invoice", new=lookup),
        ):
            await app_module._process_pending_zaps_once()

        lookup.assert_not_awaited()
        saved = store["pending_zaps"]["expired-hash"]
        self.assertTrue(saved["processing_finished"])
        self.assertEqual(saved["terminal_reason"], "invoice expired unpaid")

    async def test_old_missing_invoice_is_finished_instead_of_polled_forever(self):
        old_item = pending_zap(relays=["wss://relay.example"])
        old_item["created_at"] = int(time.time()) - 600
        store = {"pending_zaps": {"missing-hash": old_item}}

        def load_config():
            return copy.deepcopy(store)

        def save_config(config):
            store.clear()
            store.update(copy.deepcopy(config))

        request = app_module.httpx.Request(
            "GET",
            "https://lnd.example/v1/invoice/missing-hash",
        )
        response = app_module.httpx.Response(404, request=request)
        not_found = app_module.httpx.HTTPStatusError(
            "not found",
            request=request,
            response=response,
        )

        with (
            patch.object(app_module, "load_config", side_effect=load_config),
            patch.object(app_module, "save_config", side_effect=save_config),
            patch.object(
                app_module,
                "_lookup_invoice",
                new=AsyncMock(side_effect=not_found),
            ),
        ):
            await app_module._process_pending_zaps_once()

        saved = store["pending_zaps"]["missing-hash"]
        self.assertTrue(saved["processing_finished"])
        self.assertEqual(saved["terminal_reason"], "invoice not found in LND")


class TxHistorySyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_sync_requests_are_coalesced(self):
        calls = 0

        async def sync_once():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return 2

        app_module.TX_HISTORY_LAST_COMPLETED_MONOTONIC = 0.0
        with (
            patch.object(app_module, "_sync_tx_history_once", new=sync_once),
            patch.object(app_module, "TX_HISTORY_SYNC_MIN_INTERVAL", 5.0),
        ):
            results = await asyncio.gather(
                app_module.sync_tx_history(),
                app_module.sync_tx_history(),
            )

        self.assertEqual(calls, 1)
        self.assertEqual(sorted(results), [0, 2])


class ZapPublisherWakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_zap_wakes_publisher_without_waiting_for_poll_timeout(self):
        first_pass = asyncio.Event()
        second_pass = asyncio.Event()
        call_count = 0

        async def process_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                first_pass.set()
            elif call_count == 2:
                second_pass.set()

        app_module.NOSTR_ZAP_WAKE_EVENT.clear()
        with (
            patch.object(
                app_module,
                "_process_pending_zaps_once",
                new=process_once,
            ),
            patch.object(app_module, "NOSTR_ZAP_POLL_INTERVAL", 60.0),
        ):
            task = asyncio.create_task(app_module._zap_publisher_loop())
            try:
                await asyncio.wait_for(first_pass.wait(), timeout=0.5)
                started_at = time.monotonic()
                app_module.NOSTR_ZAP_WAKE_EVENT.set()
                await asyncio.wait_for(second_pass.wait(), timeout=0.5)
                self.assertLess(time.monotonic() - started_at, 0.5)
            finally:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task


if __name__ == "__main__":
    unittest.main()
