"""LNURL previews and both payment inputs diagnose HTML before any callback."""
import json
import unittest
from unittest.mock import patch

import httpx
from fastapi import HTTPException

from backend import app as backend


class LnurlMetadataResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_cloudflare_failure_is_reported_for_preview_address_and_lnurl(self):
        requests = []

        def respond(request):
            requests.append(request)
            return httpx.Response(530, text='<html>Cloudflare Error 1033 private-token</html>')

        original = httpx.AsyncClient
        with (
            patch.object(backend.httpx, 'AsyncClient', side_effect=lambda **kw:
                         original(transport=httpx.MockTransport(respond), **kw)),
            patch.object(backend, '_decode_lnurl_bech32', return_value='https://wallet.test/private-token'),
        ):
            calls = [
                lambda: backend._fetch_lnurl_metadata_from_url('https://wallet.test/private-token'),
                lambda: backend._resolve_lnurl_invoice(
                    target='alice@wallet.test', amount_sat=21),
                lambda: backend._resolve_lnurl_bech32_invoice(lnurl='lnurl1test', amount_sat=21),
            ]
            for call in calls:
                with self.assertRaises(HTTPException) as caught:
                    await call()
                self.assertEqual(caught.exception.status_code, 503)
                self.assertIn('Cloudflare Tunnel error 1033', caught.exception.detail)
                self.assertIn('wallet.test', caught.exception.detail)
                self.assertNotIn('private-token', caught.exception.detail)
                self.assertNotIn('<html>', caught.exception.detail)
        self.assertEqual(len(requests), 3, 'No callback is requested on invalid metadata')

    def test_html_access_page_has_actionable_error_without_html_or_tokens(self):
        response = httpx.Response(200, text='<html>Login private-token</html>',
                                  request=httpx.Request('GET', 'https://wallet.test/private-token'))
        with self.assertRaises(HTTPException) as caught:
            backend._parse_lnurl_metadata_response(response)
        self.assertEqual(caught.exception.status_code, 502)
        self.assertIn('access/login page', caught.exception.detail)
        self.assertNotIn('private-token', caught.exception.detail)

    def test_valid_metadata_and_existing_invoice_metadata_builder_are_preserved(self):
        metadata = {'callback': 'https://wallet.test/callback', 'minSendable': 21000,
                    'maxSendable': 21000, 'tag': 'payRequest',
                    'metadata': '[["text/plain","Cloudflare 1033 troubleshooting tip"]]'}
        self.assertEqual(backend._parse_lnurl_metadata_response(httpx.Response(200, json=metadata)), metadata)
        # The local invoice metadata builder is distinct from the response parser.
        encoded = json.loads(backend._lnurl_metadata_json('alice@wallet.test', 'Coffee'))
        self.assertIn(['text/plain', 'Coffee'], encoded)

    def test_non_object_or_rejected_responses_are_not_accepted_as_metadata(self):
        for status, value, expected in ((200, [], 502), (500, {'secret': 'private'}, 502),
                                        (200, {'status': 'ERROR', 'reason': 'private'}, 400)):
            with self.subTest(status=status, value=value), self.assertRaises(HTTPException) as caught:
                backend._parse_lnurl_metadata_response(httpx.Response(status, json=value))
            self.assertEqual(caught.exception.status_code, expected)
            self.assertNotIn('private', caught.exception.detail)
