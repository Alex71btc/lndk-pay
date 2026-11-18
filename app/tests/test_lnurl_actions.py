import base64
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs
from urllib.parse import quote
from bech32 import bech32_encode, convertbits
import httpx
from coincurve import PublicKey, PrivateKey
from coincurve.ecdsa import serialize_compact, der_to_cdata
from fastapi import HTTPException
from backend import lnurl_actions


class LnurlActionTests(unittest.IsolatedAsyncioTestCase):
    def encoded_lnurl(self, url):
        return bech32_encode('lnurl', convertbits(url.encode(), 8, 5, True)).upper()

    def test_wallet_launch_link_and_raw_qr_resolve_to_same_https_target(self):
        from backend.app import _decode_lnurl_bech32
        target = 'https://service.test/metadata/private-voucher?state=a%2Bb'
        lnurl = self.encoded_lnurl(target)
        for value in (lnurl, 'lightning:' + lnurl,
                      'https://service.test?lightning=' + lnurl,
                      'https://service.test/?lightning=' + quote('lightning:' + lnurl, safe='')):
            self.assertEqual(lnurl_actions.lnurl_url(value, _decode_lnurl_bech32), target)

    def test_wrappers_never_bypass_https_or_url_credential_validation(self):
        from backend.app import _decode_lnurl_bech32
        secure = self.encoded_lnurl('https://service.test/metadata')
        for value in ('http://service.test?lightning=' + secure,
                      'https://user:secret@service.test?lightning=' + secure,
                      'https://service.test?lightning=' + self.encoded_lnurl('http://service.test/metadata'),
                      'https://service.test?lightning=' + secure + '&lightning=' + secure):
            with self.assertRaises(HTTPException):
                lnurl_actions.lnurl_url(value, _decode_lnurl_bech32)

    def test_plain_service_query_is_preserved_and_wrapper_depth_is_bounded(self):
        from backend.app import _decode_lnurl_bech32
        target = 'https://service.test/callback?id_unique_hash=private-state&lightning=provider-value'
        self.assertEqual(lnurl_actions.lnurl_url(target, _decode_lnurl_bech32), target)
        callback = 'https://service.test/callback?lightning=' + self.encoded_lnurl('https://other.test/metadata')
        self.assertEqual(lnurl_actions.lnurl_url(callback, _decode_lnurl_bech32, unwrap_wallet=False), callback)
        for _ in range(5):
            target = 'https://service.test?lightning=' + self.encoded_lnurl(target)
        with self.assertRaises(HTTPException):
            lnurl_actions.lnurl_url(target, _decode_lnurl_bech32)

    async def test_copied_wallet_link_redeems_like_qr_without_fetching_html_wrapper(self):
        from backend.app import _decode_lnurl_bech32
        original = httpx.AsyncClient
        target = 'https://service.test/metadata/private-voucher'
        raw_lnurl = self.encoded_lnurl(target)
        for value in (raw_lnurl, 'https://service.test/?lightning=' + raw_lnurl):
            app = self.withdraw_app()
            app._decode_lnurl_bech32 = _decode_lnurl_bech32
            paths = []

            def respond(request):
                paths.append(request.url.path)
                if request.url.path == '/metadata/private-voucher':
                    return httpx.Response(200, json=self.metadata(callback=
                        'https://service.test/callback?id_unique_hash=private-state'))
                if request.url.path == '/callback':
                    self.assertEqual(request.url.params.get('id_unique_hash'), 'private-state')
                    return httpx.Response(200, json={'status': 'OK'})
                return httpx.Response(200, text='<html>LNbits launch page</html>')

            with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                       original(transport=httpx.MockTransport(respond), **kw)):
                result = await lnurl_actions.execute(app, value, 'withdraw')
            self.assertEqual(result['status'], 'OK')
            self.assertEqual(paths, ['/metadata/private-voucher', '/callback'])
            app._create_bolt11_invoice.assert_awaited_once()

    def withdraw_app(self):
        return SimpleNamespace(_decode_lnurl_bech32=lambda value: value,
            _create_bolt11_invoice=AsyncMock(return_value={'payment_request': 'lnbc-private-invoice'}))

    def metadata(self, **overrides):
        return {'tag': 'withdrawRequest', 'callback': 'https://service.test/callback',
                'k1': 'private-challenge', 'maxWithdrawable': 21000,
                'minWithdrawable': 1000, **overrides}

    async def test_html_metadata_reports_voucher_hint_without_creating_invoice(self):
        app = self.withdraw_app()
        original = httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                   original(transport=httpx.MockTransport(lambda request:
                       httpx.Response(200, text='<html>private-token</html>')), **kw)):
            with self.assertRaises(HTTPException) as caught:
                await lnurl_actions.execute(app, 'https://service.test/withdraw/private-token', 'withdraw')
        self.assertIn('withdrawal metadata', caught.exception.detail)
        self.assertIn('voucher LNURL/QR', caught.exception.detail)
        self.assertNotIn('private-token', caught.exception.detail)
        app._create_bolt11_invoice.assert_not_awaited()

    async def test_https_metadata_redirect_reaches_callback_once(self):
        app = self.withdraw_app()
        paths = []

        def respond(request):
            paths.append(request.url.path)
            if request.url.path == '/voucher':
                return httpx.Response(307, headers={'location': '/canonical'})
            if request.url.path == '/canonical':
                return httpx.Response(200, json=self.metadata())
            return httpx.Response(200, json={'status': 'OK'})

        original = httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                   original(transport=httpx.MockTransport(respond), **kw)):
            await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
        self.assertEqual(paths, ['/voucher', '/canonical', '/callback'])
        app._create_bolt11_invoice.assert_awaited_once()
        self.assertEqual(app._create_bolt11_invoice.call_args.kwargs['amount_sat'], 21)

    async def test_insecure_redirect_or_callback_is_rejected_before_invoice(self):
        original = httpx.AsyncClient
        for response in (httpx.Response(302, headers={'location': 'http://service.test/private-token'}),
                         httpx.Response(200, json=self.metadata(callback='http://service.test/private-token'))):
            app = self.withdraw_app()
            with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                       original(transport=httpx.MockTransport(lambda request: response), **kw)):
                with self.assertRaises(HTTPException) as caught:
                    await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
            self.assertIn('HTTPS', caught.exception.detail)
            self.assertNotIn('private-token', caught.exception.detail)
            app._create_bolt11_invoice.assert_not_awaited()

    async def test_html_callback_identifies_phase_without_invoice_or_token(self):
        app = self.withdraw_app()
        calls = []

        def respond(request):
            calls.append(request.url.path)
            return (httpx.Response(200, json=self.metadata()) if len(calls) == 1 else
                    httpx.Response(200, text='<html>private-challenge lnbc-private-invoice</html>'))

        original = httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                   original(transport=httpx.MockTransport(respond), **kw)):
            with self.assertRaises(HTTPException) as caught:
                await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
        self.assertIn('withdrawal callback', caught.exception.detail)
        self.assertNotIn('private-challenge', caught.exception.detail)
        self.assertNotIn('lnbc-private-invoice', caught.exception.detail)
        self.assertEqual(calls, ['/voucher', '/callback'])

    async def test_callback_redirect_is_not_followed_or_retried(self):
        app = self.withdraw_app()
        calls = []

        def respond(request):
            calls.append(request.url.path)
            return (httpx.Response(200, json=self.metadata()) if len(calls) == 1 else
                    httpx.Response(302, headers={'location': 'https://service.test/retry'}))

        original = httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                   original(transport=httpx.MockTransport(respond), **kw)):
            with self.assertRaises(HTTPException) as caught:
                await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
        self.assertIn('withdrawal callback redirected', caught.exception.detail)
        self.assertEqual(calls, ['/voucher', '/callback'])
        app._create_bolt11_invoice.assert_awaited_once()

    async def test_withdraw_preserves_lnurl_service_callback_query(self):
        app = self.withdraw_app()
        callbacks = []

        def respond(request):
            if request.url.path == '/voucher':
                return httpx.Response(200, json=self.metadata(callback=
                    'https://service.test/callback?id_unique_hash=voucher-state&token=a%2Bb&pr=old&k1=old'))
            callbacks.append(request)
            # A service may only accept a withdrawal when its voucher state survives.
            return httpx.Response(200, json={'status': 'OK' if
                request.url.params.get('id_unique_hash') == 'voucher-state' else 'ERROR'})

        original = httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                   original(transport=httpx.MockTransport(respond), **kw)):
            result = await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(dict(callbacks[0].url.params), {
            'id_unique_hash': 'voucher-state', 'token': 'a+b',
            'k1': 'private-challenge', 'pr': 'lnbc-private-invoice'})
        app._create_bolt11_invoice.assert_awaited_once()

    async def test_missing_challenge_and_service_error_do_not_create_invoice(self):
        original = httpx.AsyncClient
        for metadata in (self.metadata(k1=''), {'status': 'ERROR', 'reason': 'private-token'}):
            app = self.withdraw_app()
            with patch('backend.lnurl_actions.httpx.AsyncClient', side_effect=lambda **kw:
                       original(transport=httpx.MockTransport(lambda request:
                           httpx.Response(200, json=metadata)), **kw)):
                with self.assertRaises(HTTPException) as caught:
                    await lnurl_actions.execute(app, 'https://service.test/voucher', 'withdraw')
            self.assertNotIn('private-token', caught.exception.detail)
            app._create_bolt11_invoice.assert_not_awaited()

    async def test_lnd_auth_signature_and_withdraw_invoice(self):
        challenge = '12' * 32
        callbacks = []
        def respond(req):
            if req.url.path == '/v2/signer/signmessage':
                return httpx.Response(200, json={'signature':base64.b64encode(PrivateKey(bytes.fromhex('11'*32)).sign(b'test')).decode()})
            if req.url.path == '/withdraw':
                return httpx.Response(200,json={'tag':'withdrawRequest','callback':'https://service.test/callback','k1':'withdraw','maxWithdrawable':21000,'minWithdrawable':1000})
            callbacks.append(req)
            return httpx.Response(200,json={'status':'OK'})
        app = SimpleNamespace(_decode_lnurl_bech32=lambda x:x, LND_REST_URL='https://lnd',LND_REST_TIMEOUT=10,
            _lnd_rest_verify_setting=lambda:True,_read_macaroon_hex=lambda p:'test', LND_MACAROON_PATH='unused',
            _create_bolt11_invoice=AsyncMock(return_value={'payment_request':'lnbc-test'}))
        original=httpx.AsyncClient
        with patch('backend.lnurl_actions.httpx.AsyncClient',side_effect=lambda **kw:original(transport=httpx.MockTransport(respond),**kw)):
            await lnurl_actions.execute(app,f'https://service.test/login?tag=login&k1={challenge}','auth')
            q=dict(callbacks[0].url.params)
            self.assertTrue(PublicKey(bytes.fromhex(q['key'])).verify(bytes.fromhex(q['sig']),bytes.fromhex(challenge),hasher=None))
            await lnurl_actions.execute(app,'https://service.test/withdraw','withdraw')
            self.assertEqual(dict(callbacks[1].url.params),{'k1':'withdraw','pr':'lnbc-test'})
            self.assertEqual(app._create_bolt11_invoice.call_args.kwargs['amount_sat'],21)

    def test_der_and_compact_derive_identically_and_invalid_is_rejected(self):
        der = PrivateKey(bytes.fromhex('11'*32)).sign(b'test')
        compact = serialize_compact(der_to_cdata(der))
        self.assertEqual(lnurl_actions.normalize_signature(der), compact)
        self.assertEqual(lnurl_actions.normalize_signature(compact), compact)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            lnurl_actions.normalize_signature(b'invalid')

    def test_tls_diagnostics_hide_voucher_and_distinguish_withdraw(self):
        url='https://service.test/withdraw/private-voucher'
        request=httpx.Request('POST','http://phoenixd/lnurlwithdraw')
        response=httpx.Response(400,text='SSLHandshakeException at '+url,request=request)
        error=lnurl_actions.action_error(httpx.HTTPStatusError('bad request',request=request,response=response),'Phoenixd','withdraw')
        self.assertIn('certificate',error.detail)
        self.assertNotIn('private-voucher',error.detail)
        error=lnurl_actions.action_error(ValueError('bad data'),'LND','withdraw')
        self.assertIn('withdrawal',error.detail)
        self.assertNotIn('signer',error.detail)
