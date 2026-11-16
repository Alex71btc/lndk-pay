import unittest
from urllib.parse import parse_qs
from unittest.mock import patch

import httpx

from backend.phoenixd import PhoenixdClient


class PhoenixdClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_bolt11_and_history_requests(self):
        requests = []
        responses = [
            {"serialized": "lnbc-test", "paymentHash": "receive-hash"},
            {"reason": "payment failed"},
            [{"isPaid": True, "receivedSat": 21}],
            [{"isPaid": False, "sent": 21}],
        ]

        def respond(request):
            requests.append(request)
            return httpx.Response(200, json=responses[len(requests) - 1])

        client = PhoenixdClient("http://phoenixd:9740/", "test-password")
        async_client = httpx.AsyncClient
        with patch("backend.phoenixd.httpx.AsyncClient", side_effect=lambda **kwargs:
                   async_client(transport=httpx.MockTransport(respond), **kwargs)):
            self.assertEqual(await client.create_invoice(21, "test"), responses[0])
            self.assertEqual(await client.pay_invoice("lnbc-test", 21), responses[1])
            self.assertEqual(await client.list_incoming(limit=50, offset=20), responses[2])
            self.assertEqual(await client.list_outgoing(), responses[3])

        self.assertEqual([(r.method, r.url.path) for r in requests], [
            ("POST", "/createinvoice"), ("POST", "/payinvoice"),
            ("GET", "/payments/incoming"), ("GET", "/payments/outgoing"),
        ])
        self.assertEqual(parse_qs(requests[0].content.decode()), {
            "amountSat": ["21"], "description": ["test"],
        })
        self.assertEqual(parse_qs(requests[1].content.decode()), {
            "amountSat": ["21"], "invoice": ["lnbc-test"],
        })
        self.assertEqual(dict(requests[2].url.params), {"limit": "50", "offset": "20"})
        self.assertTrue(all(r.headers["authorization"] == "Basic OnRlc3QtcGFzc3dvcmQ="
                            for r in requests))

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(ValueError):
            PhoenixdClient("https://user:secret@example.test", "test-password")
