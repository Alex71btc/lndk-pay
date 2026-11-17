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
        self.assertEqual(dict(requests[2].url.params), {"limit": "50", "offset": "20", "all": "true"})
        self.assertTrue(all(r.headers["authorization"] == "Basic OnRlc3QtcGFzc3dvcmQ="
                            for r in requests))

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(ValueError):
            PhoenixdClient("https://user:secret@example.test", "test-password")

    async def test_offer_and_lnurl_api_forms(self):
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json='lno1test' if request.url.path == '/createoffer' else {})
        original = httpx.AsyncClient
        client = PhoenixdClient('http://phoenixd:9740', 'test-password')
        with patch('backend.phoenixd.httpx.AsyncClient', side_effect=lambda **kw: original(transport=httpx.MockTransport(respond), **kw)):
            await client.create_offer(21, 'test')
            await client.decode_offer('lno1test')
            await client.pay_offer('lno1test', 21, 'hello')
            await client.lnurl_withdraw('lnurl1test')
            await client.lnurl_auth('lnurl1auth')
        self.assertEqual([r.url.path for r in requests], ['/createoffer','/decodeoffer','/payoffer','/lnurlwithdraw','/lnurlauth'])
        self.assertEqual(parse_qs(requests[2].content.decode()), {'offer':['lno1test'],'amountSat':['21'],'message':['hello']})
        self.assertEqual(parse_qs(requests[3].content.decode()), {'lnurl':['lnurl1test']})

    async def test_plain_text_offer_and_auth_success(self):
        original = httpx.AsyncClient
        def respond(req):
            return httpx.Response(200, text='lno1test' if req.url.path == '/createoffer' else 'authentication success')
        with patch('backend.phoenixd.httpx.AsyncClient', side_effect=lambda **kw: original(transport=httpx.MockTransport(respond), **kw)):
            client = PhoenixdClient('http://phoenixd:9740', 'password')
            self.assertEqual(await client.create_offer(None, 'test'), 'lno1test')
            self.assertEqual(await client.lnurl_auth('lnurl1test'), 'authentication success')
