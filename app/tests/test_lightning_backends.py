"""Integrated BOLT11 paths with real SQLite, signed invoices and simulated HTTP."""
import asyncio
import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from bolt11 import Bolt11, encode
from bolt11.models.tags import Tags
from fastapi import HTTPException
from starlette.requests import Request

from backend import app as app_module, config, lightning_backends as backends
from backend.phoenixd import PhoenixdClient

PREIMAGE = '11' * 32
HASH = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
NODE = '02' + '22' * 32
INSTANCE = {'id': 'phoenixd-test', 'url': 'http://phoenixd:9740', 'password': 'secret-test', 'node_id': NODE}


def invoice(amount=21000):
    return encode(Bolt11(currency='bc', date=int(time.time()), amount_msat=amount,
        tags=Tags.from_dict({'p': HASH, 's': '33' * 32, 'd': 'Test invoice', 'x': 3600})), private_key='01' * 32)


def request():
    return Request({'type': 'http', 'headers': [(b'cookie', b'csrf_token=test'), (b'x-csrf-token', b'test')]})


class BackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name, value in [('APP_DATA_DIR', root), ('DB_PATH', root/'bolt12pay.db'), ('LND_REST_URL', '')]:
            patcher = patch.object(app_module, name, value); patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.object(config, 'CONFIG_PATH', str(root/'config.json')); patcher.start(); self.addCleanup(patcher.stop)
        app_module.init_db()
        config.save_config({'lightning_backend': {'active': INSTANCE['id'], 'phoenixd': INSTANCE}})
        self.service = app_module._phoenix_backend(INSTANCE)
        self.invoice = invoice()
        self.http_requests = []
        self.incoming = []
        self.outgoing = []
        self.pay_result = {'paymentHash': HASH, 'paymentPreimage': PREIMAGE, 'recipientAmountSat': 21, 'routingFeeSat': 1}
        self.client_factory = httpx.AsyncClient
        def respond(req):
            self.http_requests.append(req)
            path = req.url.path
            if path == '/getinfo': return httpx.Response(200, json={'nodeId': NODE})
            if path == '/createinvoice': return httpx.Response(200, json={'paymentHash': HASH, 'serialized': self.invoice})
            if path == '/payinvoice':
                if isinstance(self.pay_result, Exception): raise self.pay_result
                return httpx.Response(200, json=self.pay_result)
            if path == '/payments/incoming': return httpx.Response(200, json=self.incoming)
            if path == '/payments/outgoing': return httpx.Response(200, json=self.outgoing)
            if path.startswith('/payments/outgoingbyhash/'):
                return httpx.Response(200, json=self.outgoing[0]) if self.outgoing else httpx.Response(404)
            raise AssertionError(path)
        patcher = patch('backend.phoenixd.httpx.AsyncClient', side_effect=lambda **kw:
                        self.client_factory(transport=httpx.MockTransport(respond), **kw))
        patcher.start(); self.addCleanup(patcher.stop)

    def raw(self, direction, **kwargs):
        return {'paymentHash': HASH, 'invoice': self.invoice, 'subType': 'lightning',
                'isPaid': True, 'receivedSat': 21, 'requestedSat': 21, 'sent': 22, 'fees': 1000,
                'createdAt': 1700000000000, 'completedAt': 1700000001000, **kwargs}

    async def test_create_receive_pay_and_activity_without_lnd(self):
        with patch.object(app_module, '_read_macaroon_hex', side_effect=AssertionError('LND accessed')):
            with patch.object(app_module, 'require_pay_auth'):
                created = await app_module.create_invoice(app_module.CreateInvoiceRequest(
                    amount_sat=21, memo='test', backend_id=INSTANCE['id']), request())
                self.assertEqual(created.payment_hash, HASH)
                self.assertEqual(self.service.existing(HASH, 'incoming')['status'], 'pending')
                await app_module.pay_bolt11(app_module.PayBolt11Request(invoice=self.invoice, backend_id=INSTANCE['id']), request())
            self.incoming = [self.raw('incoming')]
            self.outgoing = [self.raw('outgoing')]
            await app_module._sync_tx_history_once()
            rows = app_module.list_tx_history()
            self.assertEqual(len(rows), 2)
            self.assertEqual({r['direction'] for r in rows}, {'incoming','outgoing'})
            self.assertTrue(all(r['backend_id'] == INSTANCE['id'] and r['status'] == 'settled' for r in rows))
            self.assertTrue(all(r['amount_sat'] == 21 and r['fee_sat'] == 1 for r in rows))
        self.assertEqual(await self.service.sync(), 0, 'Repeated sync must be idempotent')

    async def test_timeout_is_pending_and_cannot_be_submitted_twice(self):
        self.pay_result = httpx.ReadTimeout('timeout')
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice)
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'pending')
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice)
        self.assertEqual(sum(r.url.path == '/payinvoice' for r in self.http_requests), 1)
        self.outgoing = [self.raw('outgoing')]
        await self.service.sync()
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'settled')

    async def test_hash_only_response_is_not_settled(self):
        self.pay_result = {'paymentHash': HASH}
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice)
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'pending')

    async def test_failure_response_and_failed_history(self):
        self.pay_result = {'paymentHash': HASH, 'reason': 'insufficient funds'}
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice)
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'failed')
        self.outgoing = [self.raw('outgoing', isPaid=False)]
        await self.service.sync()
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'failed')

    async def test_switch_preserves_pending_invoice_and_sync_origin(self):
        await self.service.create(21, 'memo', 3600)
        cfg=config.load_config(); cfg['lightning_backend']['active']='lnd-default';config.save_config(cfg)
        self.incoming=[self.raw('incoming')]
        await app_module._sync_tx_history_once()
        self.assertEqual(self.service.existing(HASH, 'incoming')['status'], 'settled')
        with self.assertRaises(HTTPException): backends.selected(config.load_config(), INSTANCE['id'])

    async def test_inflight_payment_keeps_snapshot_when_selector_changes(self):
        async def send(*args):
            cfg=config.load_config();cfg['lightning_backend']['active']='lnd-default';config.save_config(cfg)
            return self.pay_result
        with patch.object(PhoenixdClient, 'pay_invoice', side_effect=send):
            await self.service.pay(self.invoice)
        self.assertEqual(self.service.existing(HASH, 'outgoing')['backend_id'], INSTANCE['id'])
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'settled')

    async def test_credentials_redacted_and_identity_change_rejected(self):
        with patch.object(app_module, '_is_pay_ui_enabled', return_value=False):
            exposed=app_module.get_setup_config(request())
        self.assertNotIn('secret-test', json.dumps(exposed))
        with patch.object(PhoenixdClient, 'get_info', AsyncMock(return_value={'nodeId': '03'+'44'*32})):
            with self.assertRaises(HTTPException): await backends.configure(config.load_config(), {'password':'new'})
        self.assertEqual(config.load_config()['lightning_backend']['phoenixd'], INSTANCE)
        self.assertEqual(Path(config.CONFIG_PATH).stat().st_mode & 0o777, 0o600)

    async def test_connection_test_does_not_save_and_empty_password_retains_secret(self):
        with patch.object(app_module,'require_pay_auth'):
            response=await app_module.test_lightning_backend({'url': INSTANCE['url'], 'password':''}, request())
            self.assertTrue(response['ok'])
            await app_module.save_lightning_backend({'active':'phoenixd','password':''}, request())
        self.assertEqual(config.load_config()['lightning_backend']['phoenixd']['password'],'secret-test')
        self.assertEqual(config.load_config()['lightning_backend']['phoenixd']['id'],INSTANCE['id'])

    async def test_auth_and_csrf_precede_connection(self):
        with self.assertRaises(HTTPException): await app_module.test_lightning_backend({},request())
        with patch.object(app_module,'require_pay_auth'):
            with self.assertRaises(HTTPException):
                await app_module.save_lightning_backend({},Request({'type':'http','headers':[]}))
        self.assertEqual(self.http_requests,[])

    async def test_history_namespaces_lnd_and_phoenix_in_both_directions(self):
        for direction in ['incoming','outgoing']:
            row=backends.history_item(self.raw(direction),direction,INSTANCE['id']);self.service.store(row)
            app_module.save_tx_history_item({**row,'backend_id':'lnd-default'})
        self.assertEqual(len(app_module.list_tx_history()),4)
        app_module.update_tx_history_metadata(HASH,memo='LND metadata')
        self.assertNotEqual(self.service.existing(HASH,'incoming')['memo'],'LND metadata')

    async def test_lnd_path_still_uses_lnd_and_public_helper_is_not_redirected(self):
        config.save_config({'lightning_backend': {'active':'lnd-default','phoenixd':INSTANCE}})
        with patch.object(app_module,'require_pay_auth'), patch.object(app_module,'_pay_bolt11_invoice',AsyncMock(return_value={})) as pay:
            await app_module.pay_bolt11(app_module.PayBolt11Request(invoice=self.invoice,backend_id='lnd-default'),request())
            pay.assert_awaited_once()
        config.save_config({'lightning_backend': {'active':INSTANCE['id'],'phoenixd':INSTANCE}})
        with patch.object(app_module,'_read_macaroon_hex',side_effect=RuntimeError('pinned LND')):
            with self.assertRaisesRegex(RuntimeError,'pinned LND'):
                await app_module._create_bolt11_invoice(amount_sat=21)
        self.assertFalse(self.http_requests)

    async def test_sync_handles_pagination_and_skips_onchain(self):
        self.incoming=[self.raw('incoming',paymentHash=f'{i:064x}') for i in range(101)]
        async def page(*,limit,offset): return self.incoming[offset:offset+limit]
        self.outgoing=[{'subType':'auto_liquidity','paymentHash':None}]
        with patch.object(PhoenixdClient,'list_incoming',side_effect=page) as listing:
            await self.service.sync()
        self.assertEqual(listing.await_count,2)
        self.assertEqual(len(app_module.list_tx_history(limit=200)),101)

    async def test_old_database_migrates_idempotently_and_preserves_metadata(self):
        with app_module._db_conn() as conn:
            conn.execute('DROP TABLE tx_history')
            conn.execute('CREATE TABLE tx_history (payment_hash TEXT PRIMARY KEY, direction TEXT NOT NULL, memo TEXT, custom_col TEXT)')
            conn.execute('INSERT INTO tx_history VALUES (?, ?, ?, ?)', (HASH,'incoming','keep me','future'))
            backends.migrate_history(conn);backends.migrate_history(conn)
            row=dict(conn.execute('SELECT * FROM tx_history').fetchone())
        self.assertEqual(row,{'payment_hash':HASH,'direction':'incoming','memo':'keep me','custom_col':'future','backend_id':'lnd-default'})

    async def test_expired_invoice_and_invoice_amount_validation(self):
        self.incoming=[self.raw('incoming',isPaid=False,isExpired=True,receivedSat=0,completedAt=None)]
        await self.service.sync()
        row=self.service.existing(HASH,'incoming');self.assertEqual(row['status'],'expired');self.assertEqual(row['amount_sat'],21)
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice,999)
        self.assertFalse(any(r.url.path=='/payinvoice' for r in self.http_requests))

    async def test_lnd_rest_creation_payment_router_fallback_and_isolation(self):
        paths=[]
        def lnd(req):
            paths.append(req.url.path)
            self.assertEqual(req.headers['Grpc-Metadata-macaroon'], 'abcd')
            if req.url.path=='/v1/invoices':
                return httpx.Response(200,json={'r_hash':base64.b64encode(bytes.fromhex(HASH)).decode(),'payment_request':self.invoice})
            if req.url.path=='/v1/channels/transactions': return httpx.Response(404,json={'code':5})
            if req.url.path=='/v2/router/send': return httpx.Response(200,json={'result':{'payment_hash':HASH,'status':'SUCCEEDED','value_sat':21,'fee_sat':1}})
            raise AssertionError(req.url.path)
        with patch.object(app_module,'LND_REST_URL','https://lnd.test'), patch.object(app_module,'LND_REST_INSECURE',True), patch.object(app_module,'_read_macaroon_hex',return_value='abcd'), patch('backend.app.httpx.AsyncClient',side_effect=lambda **kw:self.client_factory(transport=httpx.MockTransport(lnd),**kw)):
            await app_module._create_bolt11_invoice(amount_sat=21,memo='LND invoice')
            await app_module._pay_bolt11_invoice(payment_request=self.invoice,memo='LND payment')
        rows=app_module.list_tx_history(backend_id='lnd-default')
        self.assertEqual(len(rows),2)
        self.assertEqual({r['direction']:r['status'] for r in rows},{'incoming':'pending','outgoing':'settled'})
        self.assertIn('/v2/router/send',paths)

    async def test_pending_retry_wins_over_older_failed_attempt(self):
        self.outgoing=[self.raw('outgoing',isPaid=False,completedAt=None,createdAt=1700000002000),self.raw('outgoing',isPaid=False)]
        await self.service.sync()
        self.assertEqual(self.service.existing(HASH,'outgoing')['status'],'pending')
        with self.assertRaises(HTTPException): await self.service.pay(self.invoice)

    async def test_nwc_history_stays_on_lnd_and_ignores_phoenix_failure(self):
        from backend import nwc_runtime
        row=backends.history_item(self.raw('incoming'),'incoming',INSTANCE['id']);self.service.store(row)
        app_module.save_tx_history_item({**row,'backend_id':'lnd-default','memo':'LND'})
        with patch.object(nwc_runtime,'_send_nwc_success',AsyncMock()) as send:
            await nwc_runtime._handle_list_transactions_request(None,{}, {'permissions':{'get_balance':True}}, {})
            transactions=send.call_args.args[-1]['transactions']
            self.assertEqual(len(transactions),1)
            self.assertEqual(transactions[0]['description'],'LND')
        app_module.app.state.lnd_history_sync_completed=0
        with patch.object(app_module,'_sync_lnd_tx_history_once',AsyncMock(return_value=1)) as lnd:
            self.assertEqual(await app_module.sync_lnd_tx_history(),1)
            lnd.assert_awaited_once()
        self.assertEqual(self.http_requests,[])

    async def test_phoenix_only_startup_schedules_wallet_workers_without_lnd(self):
        scheduled=[]
        def capture(coroutine):
            scheduled.append(coroutine.cr_code.co_name)
            coroutine.close()
        with patch.object(app_module.asyncio,'create_task',side_effect=capture):
            await app_module.startup_background_tasks()
        self.assertIn('_tx_history_sync_loop',scheduled)
        self.assertIn('_nostr_secret_store_unlock_loop',scheduled)
        self.assertIn('start_nwc_runtime',scheduled)

    async def test_preview_uses_local_invoice_decoder(self):
        with patch.object(app_module,'require_pay_auth'), patch.object(app_module,'_read_macaroon_hex',side_effect=AssertionError('LND accessed')):
            result=await app_module.preview_pay_target(app_module.PreviewPayTargetRequest(target=self.invoice),request())
        self.assertEqual(result['amount_sat'],21)
        self.assertEqual(result['description'],'Test invoice')
        self.assertEqual(self.http_requests,[])

    async def test_http_routes_validate_backend_auth_and_csrf(self):
        session = 'phoenix-test-session'
        with patch.object(app_module,'PAY_UI_PASSWORD','test-password'), patch.dict(app_module.PAY_SESSIONS,{session:{'expires_at':int(time.time())+600}}):
            async with self.client_factory(transport=httpx.ASGITransport(app=app_module.app),base_url='http://test') as client:
                denied=await client.post('/api/setup/lightning-backend/test',json={})
                self.assertEqual(denied.status_code,401)
                client.cookies.set('pay_session',session)
                denied=await client.post('/api/setup/lightning-backend/test',json={})
                self.assertEqual(denied.status_code,403)
                client.cookies.set('csrf_token','test')
                client.headers['X-CSRF-Token']='test'
                state=await client.get('/api/lightning-backend')
                self.assertEqual(state.status_code,200)
                self.assertNotIn('secret-test',state.text)
                self.assertIn('no-store',state.headers['cache-control'])
                stale=await client.post('/api/pay-bolt11',json={'invoice':self.invoice,'backend_id':'lnd-default'})
                self.assertEqual(stale.status_code,409)
                unsupported=await client.post('/api/pay-keysend',json={})
                self.assertEqual(unsupported.status_code,409)
                created=await client.post('/api/create-invoice',json={'amount_sat':21,'backend_id':INSTANCE['id']})
                self.assertEqual(created.status_code,200,created.text)
                paid=await client.post('/api/pay-bolt11',json={'invoice':self.invoice,'backend_id':INSTANCE['id']})
                self.assertEqual(paid.status_code,200,paid.text)
                self.assertEqual(json.loads(paid.json()['raw_output'])['payment_result']['status'],'SUCCEEDED')

    async def test_phoenix_offer_payment_reusable_and_history_without_invoice(self):
        client = AsyncMock()
        client.pay_offer.return_value = self.pay_result
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))):
            result = await self.service.pay_offer('lno1test', 21, 'hello')
            self.assertEqual(result['status'], 'SUCCEEDED')
            client.pay_offer.assert_awaited_once_with('lno1test', 21, 'hello')
            await self.service.pay_offer('lno1test', 21)
        self.incoming = [self.raw('incoming', invoice=None, payerNote='hello')]
        self.outgoing = [self.raw('outgoing', invoice=None)]
        await self.service.sync()
        rows = app_module.list_tx_history()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['method'] == 'bolt12' for row in rows))
        self.assertEqual(self.service.existing(HASH, 'incoming')['payer_note'], 'hello')

    async def test_offer_timeout_blocks_retry_without_second_send(self):
        client = AsyncMock()
        client.pay_offer.side_effect = httpx.ReadTimeout('timeout')
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))):
            with self.assertRaises(HTTPException) as error:
                await self.service.pay_offer('lno1test', 21)
            self.assertEqual(error.exception.status_code, 502)
            with self.assertRaises(HTTPException) as error:
                await self.service.pay_offer('lno1test', 21)
            self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(client.pay_offer.await_count, 1)
        self.assertEqual(app_module.list_tx_history()[0]['status'], 'pending')
        self.assertEqual(app_module.list_tx_history()[0]['raw_json']['transport_error'], 'ReadTimeout')

    async def test_offer_explicit_failure_preserves_and_displays_backend_reason(self):
        client = AsyncMock()
        client.pay_offer.return_value = {
            'type': 'payment_failed', 'paymentHash': None,
            'offerId': 'test-offer-id', 'reason': 'NoResponse',
        }
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))):
            with self.assertRaises(HTTPException) as error:
                await self.service.pay_offer('lno1test', 21)
        self.assertEqual(error.exception.status_code, 400)
        self.assertIn('NoResponse', error.exception.detail)
        row = app_module.list_tx_history()[0]
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['raw_json']['reason'], 'NoResponse')
        self.assertEqual(client.pay_offer.await_count, 1, 'No automatic retry or fallback')

    async def test_offer_retry_keeps_previous_failure_and_uses_new_time_amount_and_note(self):
        client = AsyncMock()
        client.pay_offer.return_value = {'reason': 'NoResponse'}
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))):
            with patch.object(backends.time, 'time', return_value=1000):
                with self.assertRaises(HTTPException):
                    await self.service.pay_offer('lno1test', 23, 'old attempt', 'alice@example.com')
            client.pay_offer.return_value = {**self.pay_result, 'recipientAmountSat': 5000}
            with patch.object(backends.time, 'time', return_value=2000):
                await self.service.pay_offer('lno1test', 5000, None, 'alice@example.com')
        rows = app_module.list_tx_history()
        self.assertEqual(len(rows), 2, 'The failed attempt remains in history')
        settled = self.service.existing(HASH, 'outgoing')
        self.assertEqual(settled['created_at'], '2000')
        self.assertEqual(settled['amount_sat'], 5000)
        self.assertEqual(settled['memo'], '')
        failed = next(row for row in rows if row['status'] == 'failed')
        self.assertEqual(failed['created_at'], '1000')
        self.assertEqual(failed['amount_sat'], 23)
        self.assertEqual(failed['memo'], 'old attempt')

    async def test_old_offer_attempt_still_blocks_retry_after_upgrade(self):
        legacy_attempt = 'phoenix-attempt-' + hashlib.sha256(b'lno1test').hexdigest()
        self.service.store({'backend_id': INSTANCE['id'], 'payment_hash': legacy_attempt,
                            'direction': 'outgoing', 'type': 'payment', 'method': 'bolt12',
                            'status': 'pending', 'amount_sat': 21, 'raw_json': {'offer': 'lno1test'}})
        with patch.object(backends, 'checked_client', AsyncMock()) as client:
            with self.assertRaises(HTTPException) as error:
                await self.service.pay_offer('lno1test', 21)
        self.assertEqual(error.exception.status_code, 409)
        client.assert_not_awaited()

    async def test_invoice_explicit_failure_displays_backend_reason(self):
        self.pay_result = {'paymentHash': HASH, 'reason': 'InsufficientBalance'}
        with self.assertRaises(HTTPException) as error:
            await self.service.pay(self.invoice)
        self.assertEqual(error.exception.status_code, 400)
        self.assertIn('InsufficientBalance', error.exception.detail)
        self.assertEqual(self.service.existing(HASH, 'outgoing')['status'], 'failed')

    def test_payment_failure_message_is_bounded_and_single_line(self):
        message = backends.payment_failure_detail({'reason': '\nNoResponse\x00\n' + 'x'*1000}, 'BOLT12')
        self.assertNotIn('\n', message)
        self.assertNotIn('\x00', message)
        self.assertLess(len(message), 320)

    async def test_offer_routes_and_lnurl_never_access_lnd(self):
        client = AsyncMock()
        client.create_offer.return_value = 'lno1test'
        client.decode_offer.return_value = {'description': 'test'}
        client.pay_offer.return_value = self.pay_result
        client.lnurl_withdraw.return_value = {'invoice': self.invoice, 'description': 'withdraw'}
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, 'require_pay_auth'), patch.object(app_module, '_read_macaroon_hex', side_effect=AssertionError('LND accessed')):
            created = await app_module.create_offer(app_module.OfferRequest(description='test', backend_id=INSTANCE['id']), request())
            self.assertEqual(created.offer, 'lno1test')
            decoded = await app_module.decode_offer(app_module.DecodeRequest(offer='lno1test',backend_id=INSTANCE['id']))
            self.assertIn('description', decoded.raw_output)
            paid = await app_module.pay_offer(app_module.PayOfferRequest(offer='lno1test', amount_sat=21, backend_id=INSTANCE['id']), request())
            self.assertIn('SUCCEEDED', paid.raw_output)
            await app_module.phoenix_lnurl_action(app_module.PhoenixLnurlAction(lnurl='lnurl1test',action='withdraw',backend_id=INSTANCE['id']), request())
            self.assertEqual(self.service.existing(HASH, 'incoming')['method'], 'lnurl')
            await app_module.phoenix_lnurl_action(app_module.PhoenixLnurlAction(lnurl='lnurl1test',action='auth',backend_id=INSTANCE['id']), request())
            client.lnurl_auth.assert_awaited_once_with('lnurl1test')

    async def test_phoenix_address_and_lnurl_routes(self):
        async def inline(func, *args):
            return func(*args)
        with patch.object(app_module, 'require_pay_auth'), patch.object(app_module.asyncio, 'to_thread', inline), patch.object(app_module, '_resolve_bip353_address', return_value='lno1resolved'), patch.object(backends.PhoenixBackend, 'pay_offer', AsyncMock(return_value={'status':'SUCCEEDED'})) as send:
            await app_module.pay_address(app_module.PayAddressRequest(target='alice@example.com', amount_sat=21, payment_method='bolt12', backend_id=INSTANCE['id']), request())
            send.assert_awaited_once_with('lno1resolved',21,None,'alice@example.com')
        with patch.object(app_module, 'require_pay_auth'), patch.object(app_module, '_resolve_lnurl_invoice', AsyncMock(return_value={'payment_request':self.invoice})), patch.object(app_module, '_read_macaroon_hex', side_effect=AssertionError('LND accessed')):
            await app_module.pay_address(app_module.PayAddressRequest(target='alice@example.com', amount_sat=21, payment_method='lnurl', backend_id=INSTANCE['id']), request())
            self.assertEqual(self.service.existing(HASH,'outgoing')['method'],'lnurl')
        with patch.object(app_module, 'require_pay_auth'):
            with self.assertRaises(HTTPException) as err:
                await app_module.pay_offer(app_module.PayOfferRequest(offer='lno1test',amount_sat=21,backend_id='lnd-default'), request())
            self.assertEqual(err.exception.status_code,409)

    async def test_quick_backend_switch_rejects_stale_page_and_keeps_instance(self):
        with patch.object(app_module, 'require_pay_auth'), patch.object(app_module, 'LND_REST_URL', 'https://lnd.test'):
            await app_module.save_lightning_backend({'active':'lnd-default','expected_backend_id':INSTANCE['id']}, request())
            saved = config.load_config()['lightning_backend']
            self.assertEqual(saved['active'], 'lnd-default')
            self.assertEqual(saved['phoenixd'], INSTANCE)
            with self.assertRaises(HTTPException) as error:
                await app_module.save_lightning_backend({'active':'phoenixd','expected_backend_id':INSTANCE['id']}, request())
            self.assertEqual(error.exception.status_code,409)
            await app_module.save_lightning_backend({'active':'phoenixd','expected_backend_id':'lnd-default'}, request())
            self.assertEqual(config.load_config()['lightning_backend']['active'], INSTANCE['id'])
            state = await app_module.get_lightning_backend(request())
            data = json.loads(state.body)
            self.assertTrue(data['lnd_configured'])
            self.assertNotIn('password', data['phoenixd'])

    async def test_withdraw_inspection_never_redeems_and_hides_voucher(self):
        requests = []
        def respond(req):
            requests.append(req)
            return httpx.Response(200, json={'tag':'withdrawRequest','callback':'https://192.0.2.1:1234/callback/private-token','k1':'private-k1'})
        with patch.object(app_module, 'require_pay_auth'), patch('backend.app.httpx.AsyncClient',side_effect=lambda **kw:self.client_factory(transport=httpx.MockTransport(respond),**kw)), patch.object(app_module,'_create_bolt11_invoice',AsyncMock()) as create:
            result = await app_module.inspect_lnurl_withdraw(app_module.PhoenixLnurlAction(backend_id=INSTANCE['id'],lnurl='https://example.com/withdraw/private-voucher',action='withdraw'),request())
        self.assertEqual(len(requests),1)
        self.assertEqual(requests[0].method,'GET')
        self.assertEqual(result['host'],'example.com')
        self.assertEqual(result['callback_host'],'192.0.2.1:1234')
        self.assertNotIn('private',json.dumps(result))
        create.assert_not_awaited()

    async def test_withdraw_inspection_unwraps_copied_wallet_link_without_invoice(self):
        target = 'https://service.test/metadata/private-voucher?state=private-state'
        encoded = app_module.bech32.bech32_encode('lnurl',
            app_module.bech32.convertbits(target.encode(), 8, 5, True)).upper()
        requests = []

        def respond(req):
            requests.append(req)
            return httpx.Response(200, json={'tag': 'withdrawRequest',
                'callback': 'https://service.test/callback?token=private-token'})

        with (patch.object(app_module, 'require_pay_auth'),
              patch('backend.app.httpx.AsyncClient', side_effect=lambda **kw:
                    self.client_factory(transport=httpx.MockTransport(respond), **kw)),
              patch.object(app_module, '_create_bolt11_invoice', AsyncMock()) as create):
            result = await app_module.inspect_lnurl_withdraw(app_module.PhoenixLnurlAction(
                backend_id='lnd-default', lnurl='https://launch.test?lightning=' + encoded,
                action='withdraw'), request())
        self.assertEqual([str(item.url) for item in requests], [target])
        self.assertEqual(result['host'], 'service.test')
        self.assertEqual(result['tag'], 'withdrawRequest')
        self.assertNotIn('private', json.dumps(result))
        create.assert_not_awaited()

    async def test_phoenix_alias_publication_and_lnurl_remain_bound_after_switch(self):
        cfg = config.load_config()
        cfg['lnurl_base_domain'] = 'phoenixd-test.example.com'
        cfg['public_bolt12_address'] = 'bolt12@phoenixd-test.example.com'
        cfg['cloudflare'] = {'zone_name': 'example.com'}
        config.save_config(cfg)
        with patch.object(app_module, 'require_pay_auth'):
            created = app_module.create_alias(app_module.AliasCreateRequest(
                name='phoenix', description='Phoenix donations', backend_id=INSTANCE['id']), request())
        self.assertEqual(created['backend_id'], INSTANCE['id'])
        cfg = config.load_config()
        cfg['lightning_backend']['active'] = 'lnd-default'
        config.save_config(cfg)
        client = AsyncMock()
        client.create_offer.return_value = 'lno1phoenixoffer'
        with patch.object(app_module, 'require_pay_auth'), patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_create_offer_internal', side_effect=AssertionError('LNDK accessed')):
            published = await app_module.publish_alias('phoenix', request())
            await app_module.refresh_alias_offer('phoenix', request())
        self.assertEqual(published['last_offer'], 'lno1phoenixoffer')
        self.assertIn('lno1phoenixoffer', published['dns_content'])
        self.assertEqual(published['dns_name'], 'phoenix.user._bitcoin-payment.phoenixd-test.example.com')
        self.assertEqual(published['backend_id'], INSTANCE['id'])
        with patch.object(app_module, '_nostr_server_pubkey_hex', return_value=''), patch.object(app_module, '_create_bolt11_invoice', side_effect=AssertionError('LND accessed')):
            result = await app_module.lnurl_callback('phoenix', 21000, None, None, None)
        self.assertEqual(result['pr'], self.invoice)
        from urllib.parse import parse_qs
        fields = parse_qs(self.http_requests[-1].content.decode())
        self.assertNotIn('description', fields)
        metadata = app_module.lnurl_pay_metadata('phoenix').metadata
        self.assertEqual(fields['descriptionHash'][0], hashlib.sha256(metadata.encode()).hexdigest())
        self.assertEqual(self.service.existing(HASH, 'incoming')['method'], 'lightning_address')
        self.assertEqual(config.load_config()['lightning_backend']['active'], 'lnd-default')

    async def test_refresh_republishes_legacy_alias_under_full_subdomain(self):
        cfg = config.load_config()
        cfg.update(public_bolt12_address='bolt12@wallet.example.com',
                   lnurl_base_domain='wallet.example.com', dns_mode='cloudflare')
        cfg['cloudflare'] = {'zone_name': 'example.com', 'zone_id': 'parent-zone-id'}
        cfg['aliases'] = {'alice': {'backend_id': INSTANCE['id'], 'published': True,
            'dns_name': 'alice.user._bitcoin-payment.example.com',
            'last_offer': 'lno1old', 'description': 'Alice'}}
        config.save_config(cfg)
        client = AsyncMock()
        client.create_offer.return_value = 'lno1new'
        with (patch.object(app_module, 'require_pay_auth'),
              patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))),
              patch.object(app_module, '_cloudflare_upsert_txt_record', AsyncMock(return_value={})) as publish):
            result = await app_module.refresh_alias_offer('alice', request())
        publish.assert_awaited_once_with(name='alice.user._bitcoin-payment.wallet.example.com',
                                         content=app_module.build_bip353_txt_value('lno1new'))
        self.assertFalse(result['dns_needs_republish'])
        self.assertEqual(config.load_config()['cloudflare']['zone_id'], 'parent-zone-id')
        self.assertEqual(config.load_config()['aliases']['alice']['dns_name'],
                         'alice.user._bitcoin-payment.wallet.example.com')

    async def test_legacy_alias_keeps_lnd_and_missing_bound_wallet_never_falls_back(self):
        cfg = config.load_config()
        cfg['aliases'] = {'legacy': {'description': 'old address', 'amount_sat': None}}
        config.save_config(cfg)
        self.assertEqual(app_module._resolve_lnurl_alias('legacy')['backend_id'], 'lnd-default')
        with patch.object(app_module, 'require_pay_auth'):
            with self.assertRaises(HTTPException):
                app_module.create_alias(app_module.AliasCreateRequest(name='legacy', backend_id=INSTANCE['id']), request())
        with self.assertRaises(HTTPException):
            await app_module._create_bound_invoice('phoenixd-removed', amount_sat=21)
        self.assertEqual(self.http_requests, [])

    async def test_public_offer_and_setup_without_lnd(self):
        client = AsyncMock()
        client.create_offer.return_value = 'lno1public'
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_create_offer_internal', side_effect=AssertionError('LNDK accessed')):
            result = await app_module._create_bound_offer(app_module.OfferRequest(description='Public'), app_module._public_receiving_backend_id(config.load_config()))
        self.assertEqual(result.offer, 'lno1public')
        self.assertEqual(client.create_offer.call_count, 1)

    async def test_phoenix_nwc_invoice_payment_and_history_ignore_spending_selector(self):
        from backend import nwc_runtime
        connection = {'backend_id': INSTANCE['id'], 'permissions': {'get_info': True, 'pay_invoice': True, 'get_balance': True}}
        cfg = config.load_config()
        cfg['lightning_backend']['active'] = 'lnd-default'
        config.save_config(cfg)
        with patch.object(nwc_runtime, '_send_nwc_success', AsyncMock()) as success, patch.object(nwc_runtime, '_send_nwc_error', AsyncMock()) as error, patch.object(app_module, '_create_bolt11_invoice', side_effect=AssertionError('LND accessed')):
            await nwc_runtime._handle_make_invoice_request(None, {}, connection, {'amount': 21000})
            self.assertEqual(success.call_args.args[-1]['payment_hash'], HASH)
            await nwc_runtime._handle_pay_invoice_request(None, {}, connection, {'invoice': self.invoice})
            self.assertEqual(success.call_args.args[-1]['preimage'], PREIMAGE)
            self.assertEqual(success.call_args.args[-1]['fees_paid'], 1000)
            await nwc_runtime._handle_list_transactions_request(None, {}, connection, {})
            self.assertEqual(len(success.call_args.args[-1]['transactions']), 2)
            error.assert_not_awaited()
        self.assertEqual(self.service.existing(HASH, 'outgoing')['origin'], 'nwc')

    async def test_phoenix_nostr_store_unlocks_and_reopens_without_lnd_signer(self):
        root = Path(self.tmp.name)
        with patch.object(app_module, 'CONFIG_DIR', root/'config'), patch.object(app_module, 'CONFIG_JSON_PATH', root/'config.json'), patch.object(app_module, 'SECRETS_JSON_PATH', root/'config/secrets.json'), patch.object(app_module, 'NOSTR_SECRET_STORE_KEY', None), patch.object(app_module, '_request_lnd_nostr_shared_key', side_effect=AssertionError('LND signer accessed')):
            await app_module._unlock_nostr_secret_store_once()
            key = app_module.NOSTR_SECRET_STORE_KEY
            app_module.save_secrets({'nostr_server_privkey': '01' * 32})
            app_module.NOSTR_SECRET_STORE_KEY = None
            await app_module._unlock_nostr_secret_store_once()
            self.assertEqual(app_module.NOSTR_SECRET_STORE_KEY, key)
            self.assertEqual(app_module.load_secrets()['nostr_server_privkey'], '01' * 32)
            raw = app_module.SECRETS_JSON_PATH.read_text()
            self.assertNotIn('01' * 32, raw)
            self.assertIn('local-file-v1', raw)
            (root/'config/nostr-master.key').unlink()
            app_module.NOSTR_SECRET_STORE_KEY = None
            with self.assertRaises(RuntimeError):
                await app_module._unlock_nostr_secret_store_once()

    async def test_phoenix_zap_lookup_and_push_are_wallet_scoped(self):
        incoming = self.raw('incoming', preimage=PREIMAGE)
        client = AsyncMock()
        client.get_incoming.return_value = incoming
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_read_macaroon_hex', side_effect=AssertionError('LND accessed')):
            result = await app_module._lookup_invoice(HASH, INSTANCE['id'])
        self.assertTrue(result['settled'])
        self.assertEqual(result['r_preimage'], PREIMAGE)
        with app_module._db_conn() as conn:
            events = conn.execute('SELECT payment_hash FROM companion_push_events').fetchall()
        self.assertEqual([r[0] for r in events], [INSTANCE['id'] + ':' + HASH])
        app_module.companion_push.queue_settled_payment(app_module.DB_PATH, {
            'payment_hash': HASH, 'direction': 'incoming', 'status': 'settled', 'amount_sat': 21})
        with app_module._db_conn() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM companion_push_events').fetchone()[0], 2)

    async def test_phoenix_bip353_setup_publishes_dns_without_lndk(self):
        cfg = config.load_config()
        cfg['aliases'] = {}
        config.save_config(cfg)
        client = AsyncMock()
        client.create_offer.return_value = 'lno1dnsoffer'
        payload = {'public_bolt12_address': 'alice@example.com',
                   'lnurl_base_domain': 'example.com', 'dns_mode': 'cloudflare',
                   'cloudflare': {'enabled': True, 'zone_name': 'example.com',
                                  'zone_id': 'test-zone', 'api_token': 'fixture-token'}}
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_create_offer_internal', side_effect=AssertionError('LNDK accessed')), patch.object(app_module, '_cloudflare_lookup_txt_records', AsyncMock(return_value=[])), patch.object(app_module, '_cloudflare_upsert_txt_record', AsyncMock(return_value={})) as dns:
            result = await app_module.set_setup_config(payload, request())
        self.assertTrue(result['public_bip353']['published'])
        self.assertIn('lno1dnsoffer', dns.call_args.kwargs['content'])
        self.assertEqual(dns.call_args.kwargs['name'], 'alice.user._bitcoin-payment.example.com')
        self.assertEqual(config.load_config()['public_receiving_backend_id'], INSTANCE['id'])

    async def test_first_phoenix_configuration_starts_workers_without_restart(self):
        config.save_config({})
        client = AsyncMock()
        with patch.object(app_module, 'require_pay_auth'), patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_start_wallet_workers') as start:
            await app_module.save_lightning_backend({'active': 'phoenixd', 'url': INSTANCE['url'], 'password': INSTANCE['password']}, request())
        start.assert_called_once()
