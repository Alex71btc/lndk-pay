import asyncio
import json
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

import backend.nwc_runtime as nwc_runtime


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(json.loads(message))


class FakeReceiveWebSocket(FakeWebSocket):
    def __init__(self, messages):
        super().__init__()
        self.messages = list(messages)

    async def recv(self):
        message = self.messages.pop(0)
        if isinstance(message, BaseException):
            raise message
        return json.dumps(message)


class FakeConnectionContext:
    def __init__(self, websocket):
        self.websocket = websocket

    async def __aenter__(self):
        return self.websocket

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class NwcRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        nwc_runtime._nwc_requests_in_flight.clear()
        nwc_runtime._nwc_requests_seen.clear()
        nwc_runtime._nwc_pending_responses.clear()
        nwc_runtime._nwc_response_ids_by_request.clear()
        nwc_runtime._nwc_requests_seen_loaded = True

    async def test_shared_subscription_contains_all_wallet_keys_and_cursor(self):
        ws = FakeWebSocket()
        connections = [
            {"wallet_service_pubkey": "bb" * 32, "client_pubkey": "22" * 32},
            {"wallet_service_pubkey": "aa" * 32, "client_pubkey": "11" * 32},
            {"wallet_service_pubkey": "bb" * 32, "client_pubkey": "22" * 32},
        ]

        await nwc_runtime._send_nwc_relay_subscription(
            ws,
            "wss://relay.example",
            connections,
            since=1234,
        )

        request = ws.sent[0]
        self.assertEqual(request[0], "REQ")
        self.assertEqual(request[2]["authors"], ["11" * 32, "22" * 32])
        self.assertEqual(request[2]["#p"], ["aa" * 32, "bb" * 32])
        self.assertEqual(request[2]["since"], 1234)

    def test_info_event_advertises_all_supported_read_methods(self):
        methods = set(nwc_runtime._build_info_event()["content"].split())

        self.assertIn("get_balance", methods)
        self.assertIn("lookup_invoice", methods)
        self.assertIn("list_transactions", methods)

    async def test_closed_active_subscription_forces_reconnect(self):
        relay = "wss://relay.example"
        sub_id = nwc_runtime._build_relay_subscription_id(relay)

        with self.assertRaises(nwc_runtime.NwcRelaySubscriptionClosed):
            await nwc_runtime.handle_nwc_relay_message(
                FakeWebSocket(),
                relay,
                [],
                json.dumps(["CLOSED", sub_id, "rate-limited: slow down"]),
            )

    async def test_relay_loop_reconnects_after_closed_subscription(self):
        relay = "wss://relay.example"
        connections = [{
            "name": "test",
            "client_pubkey": "11" * 32,
            "wallet_service_pubkey": "22" * 32,
        }]
        first_ws = FakeReceiveWebSocket([[
            "CLOSED",
            nwc_runtime._build_relay_subscription_id(relay),
            "rate-limited: slow down",
        ]])
        second_ws = FakeReceiveWebSocket([asyncio.CancelledError()])
        connect = Mock(side_effect=[
            FakeConnectionContext(first_ws),
            FakeConnectionContext(second_ws),
        ])
        delay = AsyncMock()
        publish_info = AsyncMock()

        with (
            patch.object(nwc_runtime.websockets, "connect", new=connect),
            patch.object(nwc_runtime, "_publish_nwc_info_event", new=publish_info),
            patch.object(nwc_runtime.asyncio, "sleep", new=delay),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await nwc_runtime.nwc_relay_loop(relay, connections)

        self.assertEqual(connect.call_count, 2)
        publish_info.assert_awaited_once()
        delay.assert_awaited_once()

    async def test_rejected_response_forces_reconnect_and_stays_pending(self):
        request = {
            "id": "request-id",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        signed_response = {"id": "response-id", "kind": 23195}
        nwc_runtime._register_pending_nwc_response(request, signed_response)

        with self.assertRaises(nwc_runtime.NwcRelayPublishRejected):
            await nwc_runtime.handle_nwc_relay_message(
                FakeWebSocket(),
                "wss://relay.example",
                [],
                json.dumps(["OK", "response-id", False, "rate-limited: slow down"]),
            )

        self.assertIn("response-id", nwc_runtime._nwc_pending_responses)

    async def test_accepted_response_is_removed_from_retry_queue(self):
        request = {
            "id": "request-id",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        signed_response = {"id": "response-id", "kind": 23195}
        nwc_runtime._register_pending_nwc_response(request, signed_response)

        await nwc_runtime.handle_nwc_relay_message(
            FakeWebSocket(),
            "wss://relay.example",
            [],
            json.dumps(["OK", "response-id", True, ""]),
        )

        self.assertNotIn("response-id", nwc_runtime._nwc_pending_responses)

    async def test_permanently_rejected_response_is_not_retried(self):
        request = {
            "id": "request-id",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        signed_response = {"id": "response-id", "kind": 23195}
        nwc_runtime._register_pending_nwc_response(request, signed_response)

        await nwc_runtime.handle_nwc_relay_message(
            FakeWebSocket(),
            "wss://relay.example",
            [],
            json.dumps(["OK", "response-id", False, "invalid: bad event"]),
        )

        self.assertNotIn("response-id", nwc_runtime._nwc_pending_responses)

    async def test_reconnect_retries_only_responses_for_that_relay(self):
        matching_request = {
            "id": "matching-request",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        other_request = {
            "id": "other-request",
            "pubkey": "33" * 32,
            "tags": [["p", "44" * 32]],
        }
        matching_response = {"id": "matching-response", "kind": 23195}
        other_response = {"id": "other-response", "kind": 23195}
        nwc_runtime._register_pending_nwc_response(matching_request, matching_response)
        nwc_runtime._register_pending_nwc_response(other_request, other_response)
        ws = FakeWebSocket()

        await nwc_runtime._resend_pending_nwc_responses(
            ws,
            [{"client_pubkey": "11" * 32, "wallet_service_pubkey": "22" * 32}],
        )

        self.assertEqual(ws.sent, [["EVENT", matching_response]])

    async def test_relay_loop_retries_rate_limited_response_after_reconnect(self):
        relay = "wss://relay.example"
        request = {
            "id": "request-id",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        response = {"id": "response-id", "kind": 23195}
        connections = [{
            "name": "test",
            "client_pubkey": "11" * 32,
            "wallet_service_pubkey": "22" * 32,
        }]
        nwc_runtime._register_pending_nwc_response(request, response)

        first_ws = FakeReceiveWebSocket([[
            "OK",
            "response-id",
            False,
            "rate-limited: slow down",
        ]])
        second_ws = FakeReceiveWebSocket([asyncio.CancelledError()])
        connect = Mock(side_effect=[
            FakeConnectionContext(first_ws),
            FakeConnectionContext(second_ws),
        ])
        delay = AsyncMock()

        with (
            patch.object(nwc_runtime.websockets, "connect", new=connect),
            patch.object(nwc_runtime, "_publish_nwc_info_event", new=AsyncMock()),
            patch.object(nwc_runtime, "_send_nwc_relay_subscription", new=AsyncMock()),
            patch.object(nwc_runtime.asyncio, "sleep", new=delay),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await nwc_runtime.nwc_relay_loop(relay, connections)

        self.assertEqual(first_ws.sent, [["EVENT", response]])
        self.assertEqual(second_ws.sent, [["EVENT", response]])
        delay.assert_awaited_once()

    async def test_duplicate_request_retries_response_without_reexecuting(self):
        event = {
            "id": "request-id",
            "pubkey": "11" * 32,
            "tags": [["p", "22" * 32]],
        }
        signed_response = {"id": "response-id", "kind": 23195}
        nwc_runtime._register_pending_nwc_response(event, signed_response)
        nwc_runtime._nwc_requests_seen[event["id"]] = time.time()
        execute = AsyncMock()
        ws = FakeWebSocket()

        with patch.object(
            nwc_runtime,
            "_handle_request_event_once",
            new=execute,
        ):
            await nwc_runtime._handle_request_event(ws, {}, event)

        execute.assert_not_awaited()
        self.assertEqual(ws.sent, [["EVENT", signed_response]])

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
