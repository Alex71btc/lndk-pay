"""Isolated production-function tests; no running LND or application data needed."""
import ast
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

SOURCE = Path(__file__).resolve().parents[1] / 'backend/app.py'


class HttpError(Exception):
    def __init__(self, status_code, detail):
        self.status_code, self.detail = status_code, detail


def functions():
    names = {'_payment_failure_detail', '_active_channel_liquidity',
             '_explain_payment_failure', 'api_liquidity'}
    nodes = [n for n in ast.parse(SOURCE.read_text()).body
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    for node in nodes:
        node.decorator_list = []
    context = {'HTTPException': HttpError, 'StarletteRequest': object,
               'LND_REST_URL': 'https://lnd.invalid', 'LND_REST_INSECURE': False,
               'LND_TLS_CERT_PATH': '/test/cert', 'LND_MACAROON_PATH': '/test/mac',
               '_read_macaroon_hex': Mock(return_value='test-macaroon'),
               '_no_store_headers': lambda: {'Cache-Control': 'no-store'},
               'require_pay_auth': Mock(), '_lnd_getinfo': AsyncMock(return_value={'alias': 'local'}),
               'JSONResponse': lambda body, headers: (body, headers)}
    exec(compile(ast.Module(nodes, type_ignores=[]), str(SOURCE), 'exec'), context)
    return context


class PaymentLiquidityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ns = functions()

    def test_no_route_does_not_imply_local_liquidity(self):
        classify = self.ns['_payment_failure_detail']
        for reason in ('FAILURE_REASON_NO_ROUTE', 'no route found', '2'):
            self.assertEqual(classify(reason), {'code': 'no_route', 'liquidity': True})
            self.assertEqual(classify(reason, 100, [{'outgoing_sat': 150}])['code'], 'no_route')

    def test_explicit_lnd_insufficient_balance_and_upper_bound(self):
        classify = self.ns['_payment_failure_detail']
        self.assertEqual(classify('FAILURE_REASON_INSUFFICIENT_BALANCE')['code'], 'local_liquidity')
        self.assertEqual(classify('5')['code'], 'local_liquidity')
        self.assertEqual(classify('no route', 101, [{'outgoing_sat': 100}])['code'], 'no_route_local_liquidity')
        self.assertEqual(classify('no route', 100, [])['code'], 'no_route_local_liquidity')
        # Equality is not evidence of insufficient liquidity: fees/reserves unknown.
        self.assertEqual(classify('no route', 100, [{'outgoing_sat': 100}])['code'], 'no_route')

    async def test_unavailable_lnd_is_not_zero_liquidity(self):
        self.ns['_active_channel_liquidity'] = AsyncMock(side_effect=OSError('offline'))
        result = await self.ns['_explain_payment_failure']('FAILURE_REASON_NO_ROUTE', 100)
        self.assertEqual(result['code'], 'no_route')

    def test_unknown_failure_is_preserved_and_other_lnd_reasons_are_separate(self):
        classify = self.ns['_payment_failure_detail']
        self.assertIsNone(classify('temporary unknown failure'))
        self.assertEqual(classify('FAILURE_REASON_TIMEOUT')['code'], 'timeout')
        self.assertEqual(classify('FAILURE_REASON_INCORRECT_PAYMENT_DETAILS')['code'], 'incorrect_details')

    def channel_client(self, channels):
        response = Mock()
        response.json.return_value = {'channels': channels}
        client = AsyncMock()
        client.get.return_value = response
        manager = AsyncMock()
        manager.__aenter__.return_value = client
        self.ns['httpx'] = SimpleNamespace(AsyncClient=Mock(return_value=manager))
        return client

    async def test_active_channels_only_and_no_mutation(self):
        client = self.channel_client([
            {'active': True, 'chan_id': '42', 'local_balance': '123', 'remote_balance': '456'},
            {'active': False, 'chan_id': '43', 'local_balance': '99999', 'remote_balance': '1'},
        ])
        result = await self.ns['_active_channel_liquidity']()
        self.assertEqual(result, [{'channel_id': '42', 'outgoing_sat': 123, 'incoming_sat': 456}])
        client.get.assert_awaited_once_with('https://lnd.invalid/v1/channels',
            headers={'Grpc-Metadata-macaroon': 'test-macaroon'}, params={'active_only': 'true'})
        client.post.assert_not_called()

    async def test_malformed_balance_is_unavailable_not_zero(self):
        self.channel_client([{'active': True, 'chan_id': '42', 'remote_balance': '4'}])
        with self.assertRaises(KeyError):
            await self.ns['_active_channel_liquidity']()

    async def test_expired_session_is_rejected_before_lnd_access(self):
        self.ns['require_pay_auth'].side_effect = HttpError(401, 'expired')
        lnd = self.ns['_active_channel_liquidity'] = AsyncMock()
        with self.assertRaises(HttpError) as caught:
            await self.ns['api_liquidity'](object())
        self.assertEqual(caught.exception.status_code, 401)
        lnd.assert_not_called()

    async def test_endpoint_no_store_and_unavailable_status(self):
        self.ns['_active_channel_liquidity'] = AsyncMock(return_value=[])
        body, headers = await self.ns['api_liquidity'](object())
        self.assertEqual(body, {'channels': [], 'local_alias': 'local'})
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.ns['_active_channel_liquidity'].side_effect = OSError('offline')
        with self.assertRaises(HttpError) as caught:
            await self.ns['api_liquidity'](object())
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(caught.exception.detail['code'], 'lnd_unavailable')
