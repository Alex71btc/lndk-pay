import json
import time
import unittest
from unittest.mock import AsyncMock, patch

import backend.nwc_runtime as nwc_runtime


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(json.loads(message))


class NwcRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        nwc_runtime._nwc_requests_in_flight.clear()
        nwc_runtime._nwc_requests_seen.clear()
        nwc_runtime._nwc_requests_seen_loaded = True

    async def test_shared_subscription_contains_all_wallet_keys_and_cursor(self):
        ws = FakeWebSocket()
        connections = [
            {"wallet_service_pubkey": "bb" * 32},
            {"wallet_service_pubkey": "aa" * 32},
            {"wallet_service_pubkey": "bb" * 32},
        ]

        await nwc_runtime._send_nwc_relay_subscription(
            ws,
            "wss://relay.example",
            connections,
            since=1234,
        )

        request = ws.sent[0]
        self.assertEqual(request[0], "REQ")
        self.assertEqual(request[2]["#p"], ["aa" * 32, "bb" * 32])
        self.assertEqual(request[2]["since"], 1234)

    async def test_duplicate_event_is_executed_only_once(self):
        event = {
            "id": "event-id",
            "created_at": int(time.time()),
        }
        execute = AsyncMock()

        with patch.object(
            nwc_runtime,
            "_handle_request_event_once",
            new=execute,
        ):
            await nwc_runtime._handle_request_event(None, {}, event)
            await nwc_runtime._handle_request_event(None, {}, event)

        execute.assert_awaited_once()

    def test_reconnect_backoff_is_bounded_and_honors_retry_after(self):
        class RelayError(Exception):
            headers = {"Retry-After": "45"}

        self.assertEqual(
            nwc_runtime._nwc_reconnect_delay(1, RelayError(), jitter=1.0),
            45.0,
        )
        self.assertEqual(
            nwc_runtime._nwc_reconnect_delay(20, RuntimeError(), jitter=1.0),
            nwc_runtime.NWC_RECONNECT_MAX_SECONDS,
        )


if __name__ == "__main__":
    unittest.main()
