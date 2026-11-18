import base64
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs
import httpx
from coincurve import PublicKey, PrivateKey
from coincurve.ecdsa import serialize_compact, der_to_cdata
from backend import lnurl_actions


class LnurlActionTests(unittest.IsolatedAsyncioTestCase):
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
