"""Integrated BOLT11 paths with real SQLite, signed invoices and simulated HTTP."""
import asyncio
import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

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

    def pair_companion(self):
        push = app_module.companion_push
        token, _ = push.create_pairing_token(app_module.DB_PATH)
        push.register_device(
            app_module.DB_PATH, pairing_token=token, name='Test Companion',
            endpoint='https://push.example.com/phoenixd-test',
            p256dh=base64.urlsafe_b64encode(b'\x04' + b'\x11' * 64).decode().rstrip('='),
            auth=base64.urlsafe_b64encode(b'\x22' * 16).decode().rstrip('='),
        )

    async def test_phoenix_history_import_with_paired_companion(self):
        self.pair_companion()
        push = app_module.companion_push
        instance = {**INSTANCE, 'id': 'phoenixd-import'}
        config.save_config({'lightning_backend': {'active': instance['id'], 'phoenixd': instance}})
        service = app_module._phoenix_backend(instance)
        start = push.phoenixd_push_start(app_module.DB_PATH, instance['id'])
        missing_time_hash = 'ab' * 32
        live = self.raw('incoming', completedAt=start + 1)
        historical = [
            self.raw('incoming', paymentHash=f'{i:064x}', completedAt=start - 1)
            for i in range(100)
        ]
        client = AsyncMock()
        client.list_incoming.side_effect = [
            historical,
            [self.raw('incoming', paymentHash=missing_time_hash, completedAt=None), live],
        ]
        client.list_outgoing.return_value = []
        with patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))):
            self.assertEqual(await service.sync(), 102)
            self.assertEqual([call.kwargs['offset'] for call in client.list_incoming.await_args_list], [0, 100])
        sender = AsyncMock()
        self.assertEqual(await push.dispatch_due(
            app_module.DB_PATH, vapid_private_key='test', vapid_subject='mailto:test@example.com',
            sender=sender,
        ), 1)
        self.assertEqual(json.loads(sender.await_args.kwargs['data'])['payment_hash'], HASH)
        self.assertEqual(len(app_module.list_tx_history(limit=200)), 102)

        app_module.init_db()
        with patch.object(time, 'time_ns', return_value=(start + 60_000) * 1_000_000):
            restarted = app_module._phoenix_backend(instance)
            self.assertEqual(push.phoenixd_push_start(app_module.DB_PATH, instance['id']), start)
        self.incoming = [live, {**historical[0], 'description': 'History metadata updated'}]
        await restarted.sync()
        self.assertEqual(await push.dispatch_due(
            app_module.DB_PATH, vapid_private_key='test', vapid_subject='mailto:test@example.com',
            sender=sender,
        ), 0)
        sender.assert_awaited_once()

    async def test_upgrade_discards_legacy_phoenix_pushes_only(self):
        self.pair_companion()
        push = app_module.companion_push
        now = int(time.time())
        for payment_hash, completed_at in (
            (HASH, (now - 3600) * 1000), ('ab' * 32, now * 1000), ('cd' * 32, None),
        ):
            item = backends.history_item(
                self.raw('incoming', paymentHash=payment_hash, completedAt=completed_at),
                'incoming', INSTANCE['id'],
            )
            app_module.save_tx_history_item(item)
            push.queue_settled_payment(app_module.DB_PATH, item, now=now)
        push.queue_settled_payment(app_module.DB_PATH, {
            'payment_hash': HASH, 'direction': 'incoming', 'status': 'settled', 'amount_sat': 21,
        }, now=now)
        with app_module._db_conn() as conn:
            conn.execute("""
                UPDATE companion_push_deliveries SET status = 'retry', attempts = 1
                WHERE event_id = (SELECT id FROM companion_push_events WHERE payment_hash = ?)
            """, (INSTANCE['id'] + ':' + HASH,))

        push.discard_legacy_phoenixd_deliveries(app_module.DB_PATH)
        push.discard_legacy_phoenixd_deliveries(app_module.DB_PATH)
        sender = AsyncMock()
        self.assertEqual(await push.dispatch_due(
            app_module.DB_PATH, vapid_private_key='test', vapid_subject='mailto:test@example.com',
            sender=sender, now=now,
        ), 2)
        payloads = [json.loads(call.kwargs['data']) for call in sender.await_args_list]
        self.assertEqual(
            {(item['backend'], item['payment_hash']) for item in payloads},
            {('lnd', HASH), ('phoenixd', 'ab' * 32)},
        )
        self.assertEqual(len(app_module.list_tx_history()), 3)
        self.assertEqual(len(push.list_devices(app_module.DB_PATH)), 1)

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
        with patch.object(app_module,'PAY_UI_PASSWORD','test-password'), patch.dict(app_module.PAY_SESSIONS, clear=True):
            async with self.client_factory(transport=httpx.ASGITransport(app=app_module.app),base_url='http://test') as client:
                denied=await client.post('/api/setup/lightning-backend/test',json={})
                self.assertEqual(denied.status_code,401)
                session = app_module._create_pay_session(app_module._get_effective_ui_password_hash())
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
            self.http_requests.clear()
            with self.assertRaises(HTTPException) as error:
                await app_module.save_lightning_backend({'active': 'phoenixd', 'url': ''}, request())
            self.assertEqual(error.exception.status_code, 400)
            self.assertEqual(self.http_requests, [])

    async def test_pause_stops_background_sync_and_pushes_until_resumed(self):
        self.pair_companion()
        push = app_module.companion_push
        now_ms = time.time_ns() // 1_000_000
        self.incoming = [self.raw('incoming', completedAt=now_ms)]
        await self.service.sync()
        lnd_sync = AsyncMock(return_value=0)
        with (
            patch.object(app_module, 'require_pay_auth'),
            patch.object(app_module, 'LND_REST_URL', 'https://lnd.test'),
            patch.object(app_module, '_start_wallet_workers'),
            patch.object(app_module, '_sync_lnd_tx_history_once', lnd_sync),
        ):
            paused = await app_module.manage_phoenix_connection(
                app_module.PhoenixConnectionAction(
                    action='pause', backend_id=INSTANCE['id'], hide_alias_pages=True,
                ), request())
            self.assertEqual(json.loads(paused.body)['active'], 'lnd-default')
            self.assertTrue(json.loads(paused.body)['phoenixd']['alias_pages_hidden'])
            self.assertTrue(config.load_config()['lightning_backend']['phoenixd']['paused'])
            alias = {'backend_id': INSTANCE['id']}
            self.assertTrue(backends.alias_page_hidden(config.load_config(), alias))
            with self.assertRaises(HTTPException):
                backends.bound(config.load_config(), INSTANCE['id'])
            self.http_requests.clear()
            await app_module._sync_tx_history_once()
            self.assertEqual(self.http_requests, [])
            lnd_sync.assert_awaited_once()
            sender = AsyncMock()
            self.assertEqual(await push.dispatch_due(
                app_module.DB_PATH, vapid_private_key='test', vapid_subject='mailto:test@example.com',
                sender=sender,
            ), 0)
            self.assertEqual(len(app_module.list_tx_history()), 1)

            with patch.object(time, 'time_ns', return_value=(now_ms + 2000) * 1_000_000):
                await app_module.manage_phoenix_connection(
                    app_module.PhoenixConnectionAction(action='resume', backend_id=INSTANCE['id']), request())
            config_after = config.load_config()
            self.assertFalse(backends.alias_page_hidden(config_after, alias))
            self.assertEqual(config_after['lightning_backend']['active'], 'lnd-default')
            self.assertEqual(backends.bound(config_after, INSTANCE['id'])['password'], INSTANCE['password'])
            self.incoming += [
                self.raw('incoming', paymentHash='ab' * 32, completedAt=now_ms + 1000),
                self.raw('incoming', paymentHash='cd' * 32, completedAt=now_ms + 3000),
            ]
            await app_module._sync_tx_history_once()
            self.assertEqual(len(app_module.list_tx_history()), 3)
            self.assertEqual(await push.dispatch_due(
                app_module.DB_PATH, vapid_private_key='test', vapid_subject='mailto:test@example.com',
                sender=sender,
            ), 1)
            self.assertEqual(json.loads(sender.await_args.kwargs['data'])['payment_hash'], 'cd' * 32)

    async def test_remove_keeps_history_and_reattaches_only_the_same_wallet(self):
        self.incoming = [self.raw('incoming')]
        await self.service.sync()
        with patch.object(app_module, 'require_pay_auth'), patch.object(app_module, '_start_wallet_workers'):
            removed = await app_module.manage_phoenix_connection(
                app_module.PhoenixConnectionAction(action='remove', backend_id=INSTANCE['id']), request())
            self.assertIsNone(json.loads(removed.body)['phoenixd'])
            self.assertNotIn(INSTANCE['password'], Path(config.CONFIG_PATH).read_text())
            self.assertEqual(len(app_module.list_tx_history()), 1)
            self.assertEqual(config.load_config()['public_receiving_backend_id'], INSTANCE['id'])
            with self.assertRaises(HTTPException):
                backends.bound(config.load_config(), INSTANCE['id'])
            with patch.object(backends, 'checked_client', AsyncMock(return_value=(None, '02' + '44' * 32))):
                different = await backends.configure(config.load_config(), INSTANCE)
            self.assertNotEqual(different['lightning_backend']['phoenixd']['id'], INSTANCE['id'])

            await app_module.save_lightning_backend({'url': INSTANCE['url'], 'password': INSTANCE['password']}, request())
            self.assertEqual(backends.bound(config.load_config(), INSTANCE['id'])['node_id'], NODE)
            with self.assertRaises(HTTPException) as error:
                await app_module.manage_phoenix_connection(
                    app_module.PhoenixConnectionAction(action='remove', backend_id=INSTANCE['id']), request())
            self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(await app_module._sync_tx_history_once(), 0)
            self.assertEqual(len(app_module.list_tx_history()), 1)

    async def test_remove_with_history_deletes_only_phoenix_rows_and_notifications(self):
        self.pair_companion()
        push = app_module.companion_push
        self.incoming = [self.raw('incoming', completedAt=time.time_ns() // 1_000_000)]
        await self.service.sync()
        lnd = {**app_module.list_tx_history()[0], 'backend_id': 'lnd-default'}
        app_module.save_tx_history_item(lnd)
        push.queue_settled_payment(app_module.DB_PATH, lnd)
        with patch.object(app_module, 'require_pay_auth'):
            await app_module.manage_phoenix_connection(
                app_module.PhoenixConnectionAction(
                    action='remove', backend_id=INSTANCE['id'], delete_history=True,
                ), request())
        self.assertEqual([row['backend_id'] for row in app_module.list_tx_history()], ['lnd-default'])
        with app_module._db_conn() as db:
            self.assertEqual([row[0] for row in db.execute('SELECT payment_hash FROM companion_push_events')], [HASH])
        self.assertEqual(len(push.list_devices(app_module.DB_PATH)), 1)

    async def test_remove_publications_scopes_aliases_offer_history_and_dns_to_the_wallet(self):
        cfg = config.load_config()
        cfg.update(
            dns_mode='cloudflare', public_bolt12_address='pay@wallet.example',
            public_receiving_backend_id=INSTANCE['id'],
            cloudflare={'enabled': True, 'zone_name': 'example', 'zone_id': 'zone', 'api_token': 'test-token'},
            aliases={
                'alice': {'backend_id': INSTANCE['id'], 'last_offer': 'lno1alias', 'dns_name': 'alice.user._bitcoin-payment.wallet.example'},
                'bob': {'backend_id': 'lnd-default', 'last_offer': 'lno1lnd', 'dns_name': 'bob.user._bitcoin-payment.wallet.example'},
            },
        )
        config.save_config(cfg)
        with app_module._db_conn() as db:
            db.executemany("INSERT INTO backend_objects VALUES ('offer', ?, ?)", [
                ('lno1phoenix', INSTANCE['id']), ('lno1public', INSTANCE['id']),
            ])
        for item_id, offer in (
            ('phx', 'lno1phoenix'), ('alias', 'lno1alias'), ('lnd', 'lno1lnd'), ('public', 'lno1public'),
        ):
            app_module.save_offer_history_item({'id': item_id, 'offer': offer})
        saved_dns = 'tip.user._bitcoin-payment.wallet.example'
        app_module.save_history_bip353('phx', 'tip', 'tip@wallet.example', saved_dns)
        app_module.save_history_bip353('public', 'pay', 'pay@wallet.example',
                                        'PAY.user._bitcoin-payment.wallet.example.')
        lnd_dns = 'bob.user._bitcoin-payment.wallet.example'
        app_module.save_history_bip353('lnd', 'bob', 'bob@wallet.example', lnd_dns)
        delete_dns = AsyncMock(return_value={'retained_bolt12': False})
        with (
            patch.object(app_module, 'require_pay_auth'),
            patch.object(app_module, 'get_bip353_base_domain', return_value='wallet.example'),
            patch.object(app_module, '_cloudflare_delete_txt_record', delete_dns),
            patch.object(app_module, 'LNURL_ALIAS_MODE', 'open'),
        ):
            response = await app_module.manage_phoenix_connection(app_module.PhoenixConnectionAction(
                action='remove', backend_id=INSTANCE['id'], delete_publications=True,
            ), request())
            with self.assertRaises(HTTPException) as missing:
                app_module._resolve_lnurl_alias('alice')
            self.assertEqual(missing.exception.status_code, 404)
        self.assertEqual({call.kwargs['name']: call.kwargs['expected_offers'] for call in delete_dns.await_args_list}, {
            'alice.user._bitcoin-payment.wallet.example': {'lno1alias'},
            'alice.user._bitcoin-payment.example': {'lno1alias'},
            saved_dns: {'lno1phoenix'},
        })
        self.assertNotIn('manual_dns_names', json.loads(response.body))
        self.assertEqual([item['id'] for item in app_module.list_offer_history()], ['lnd'])
        self.assertEqual([item['dns_name'] for item in app_module.list_all_history_bip353()], [lnd_dns])
        self.assertEqual(set(config.load_config()['aliases']), {'bob'})
        self.assertEqual(config.load_config()['public_receiving_backend_id'], INSTANCE['id'])

    async def test_publication_cleanup_failure_keeps_data_for_retry(self):
        cfg = config.load_config()
        dns_name = 'alice.user._bitcoin-payment.wallet.example'
        cfg.update(
            dns_mode='cloudflare', cloudflare={'enabled': True, 'zone_name': 'example',
                                             'zone_id': 'zone', 'api_token': 'test-token'},
            aliases={'alice': {'backend_id': INSTANCE['id'], 'last_offer': 'lno1alias', 'dns_name': dns_name}},
        )
        config.save_config(cfg)
        app_module.save_offer_history_item({'id': 'phx', 'offer': 'lno1alias'})
        action = app_module.PhoenixConnectionAction(
            action='remove', backend_id=INSTANCE['id'], delete_publications=True,
        )
        with (
            patch.object(app_module, 'require_pay_auth'),
            patch.object(app_module, 'get_bip353_base_domain', return_value='wallet.example'),
            patch.object(app_module, '_cloudflare_delete_txt_record', AsyncMock(
                side_effect=HTTPException(502, 'DNS offline'),
            )),
        ):
            with self.assertRaises(HTTPException):
                await app_module.manage_phoenix_connection(action, request())
            self.assertTrue(config.load_config()['lightning_backend']['phoenixd']['paused'])
            self.assertIn('alice', config.load_config()['aliases'])
            self.assertIsNotNone(app_module.get_offer_history_item('phx'))

            cfg = config.load_config()
            cfg['dns_mode'] = 'manual'
            config.save_config(cfg)
            response = await app_module.manage_phoenix_connection(action, request())
        self.assertEqual(json.loads(response.body)['manual_dns_names'], [
            'alice.user._bitcoin-payment.example', dns_name,
        ])
        self.assertIsNone(app_module.get_offer_history_item('phx'))

    async def test_scoped_dns_deletion_keeps_unrelated_txt_at_the_same_name(self):
        name = 'alice.user._bitcoin-payment.wallet.example'
        cloudflare = {'enabled': True, 'zone_name': 'example', 'zone_id': 'zone', 'api_token': 'test-token'}
        records = [
            {'id': key, 'name': name, 'type': 'TXT', 'content': content}
            for key, content in (
                ('owned', '"bitcoin:?lno=lno1phoenix"'),
                ('other', '"bitcoin:?lno=lno1lnd"'),
                ('extra', '"bitcoin:?lno=lno1phoenix&lightning=lnbc1other"'),
                ('txt', '"other text"'),
            )
        ]
        client = AsyncMock()
        client.delete.return_value = httpx.Response(200, json={'success': True})
        with (
            patch.object(app_module, '_cloudflare_lookup_txt_records', AsyncMock(return_value=records)),
            patch.object(app_module.httpx, 'AsyncClient') as make_client,
        ):
            make_client.return_value.__aenter__.return_value = client
            result = await app_module._cloudflare_delete_txt_record(
                name=name, cloudflare_config=cloudflare, expected_offers={'lno1phoenix'},
            )
        self.assertEqual(result['deleted_record_ids'], ['owned'])
        self.assertTrue(result['retained_bolt12'])
        client.delete.assert_awaited_once()
        self.assertTrue(client.delete.await_args.args[0].endswith('/owned'))

    async def test_scoped_dns_deletion_matches_long_offers_split_into_txt_chunks(self):
        name = 'alice.user._bitcoin-payment.wallet.example'
        cloudflare = {'enabled': True, 'zone_name': 'example', 'zone_id': 'zone', 'api_token': 'test-token'}
        offer = 'lno1' + 'qp' * 220
        content = f'bitcoin:?lno={offer}'
        chunked = ' '.join(f'"{content[i:i + 255]}"' for i in range(0, len(content), 255))
        records = [
            {'id': 'long', 'name': name, 'type': 'TXT', 'content': chunked},
            {'id': 'other', 'name': name, 'type': 'TXT', 'content': chunked + '"&lightning=lnbc1other"'},
        ]
        client = AsyncMock()
        client.delete.return_value = httpx.Response(200, json={'success': True})
        with (
            patch.object(app_module, '_cloudflare_lookup_txt_records', AsyncMock(return_value=records)),
            patch.object(app_module.httpx, 'AsyncClient') as make_client,
        ):
            make_client.return_value.__aenter__.return_value = client
            result = await app_module._cloudflare_delete_txt_record(
                name=name, cloudflare_config=cloudflare, expected_offers={offer},
            )
        self.assertEqual(result['deleted_record_ids'], ['long'])
        self.assertTrue(result['retained_bolt12'])
        client.delete.assert_awaited_once()
        self.assertTrue(client.delete.await_args.args[0].endswith('/long'))

    async def test_pause_invalidates_history_sync_already_in_flight(self):
        loading = asyncio.Event()
        release = asyncio.Event()

        async def list_incoming(**kwargs):
            loading.set()
            await release.wait()
            return [self.raw('incoming')]

        client = AsyncMock()
        client.list_incoming.side_effect = list_incoming
        with patch.object(backends, 'checked_client', return_value=(client, NODE)), patch.object(app_module, 'require_pay_auth'):
            sync = asyncio.create_task(self.service.sync())
            try:
                await asyncio.wait_for(loading.wait(), 1)
                await app_module.manage_phoenix_connection(
                    app_module.PhoenixConnectionAction(action='pause', backend_id=INSTANCE['id']), request())
            finally:
                release.set()
            with self.assertRaises(HTTPException):
                await sync
        self.assertEqual(app_module.list_tx_history(), [])
        client.list_outgoing.assert_not_awaited()

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

    async def test_alias_renewal_recovers_after_outage_without_reload_or_wallet_fallback(self):
        async def inline_thread(function, *args, **kwargs):
            return function(*args, **kwargs)

        for owner in ('lnd-default', INSTANCE['id']):
            with self.subTest(owner=owner):
                cfg = config.load_config()
                cfg['lightning_backend']['active'] = (
                    INSTANCE['id'] if owner == 'lnd-default' else 'lnd-default')
                cfg['dns_mode'] = 'manual'
                cfg['aliases'] = {'recovery': {'backend_id': owner,
                    'description': 'Recovery test', 'amount_sat': 24,
                    'published': True, 'last_offer': 'lno1original'}}
                config.save_config(cfg)
                saved = config.load_config()
                unavailable = HTTPException(502, 'Selected receiving wallet is offline')
                client = AsyncMock()
                client.create_offer.return_value = 'lno1recoveredphoenix'
                lnd_outcomes = ([unavailable, app_module.OfferResponse(
                    offer='lno1recoveredlnd', raw_output='test')]
                    if owner == 'lnd-default' else AssertionError('Unexpected LND fallback'))
                phoenix_outcomes = ([unavailable, (client, NODE)]
                    if owner == INSTANCE['id'] else AssertionError('Unexpected Phoenixd fallback'))
                with (patch.object(app_module, 'require_pay_auth'),
                      patch.object(app_module.asyncio, 'to_thread', AsyncMock(side_effect=inline_thread)),
                      patch.object(app_module, '_create_offer_internal', side_effect=lnd_outcomes),
                      patch.object(backends, 'checked_client', AsyncMock(side_effect=phoenix_outcomes)),
                      patch.object(app_module, '_cloudflare_upsert_txt_record', AsyncMock()) as dns):
                    with self.assertRaises(HTTPException) as failed:
                        await app_module.refresh_alias_offer('recovery', request())
                    self.assertEqual(failed.exception.status_code, 502)
                    self.assertEqual(config.load_config(), saved)
                    # Same endpoint and app state: only the transport recovers.
                    result = await app_module.refresh_alias_offer('recovery', request())
                    dns.assert_not_awaited()
                self.assertEqual(result['backend_id'], owner)
                self.assertNotEqual(result['last_offer'], 'lno1original')
                self.assertEqual(config.load_config()['lightning_backend'], saved['lightning_backend'])

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
            self.assertEqual({tx['type'] for tx in success.call_args.args[-1]['transactions']},
                             {'incoming', 'outgoing'})
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
        incoming = self.raw('incoming', preimage=PREIMAGE, completedAt=time.time_ns() // 1_000_000)
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

    async def test_public_bip353_repair_can_explicitly_move_removed_phoenixd_address_to_lnd(self):
        address = 'pay@wallet.example'
        cfg = {
            'dns_mode': 'cloudflare',
            'public_bolt12_address': address,
            'public_receiving_backend_id': INSTANCE['id'],
            'cloudflare': {'zone_name': 'example', 'zone_id': 'zone', 'api_token': 'token'},
            'aliases': {'alice': {'backend_id': INSTANCE['id'], 'last_offer': 'lno1phoenix'}},
        }
        config.save_config(cfg)
        offer = app_module.OfferResponse(offer='lno1lnd', raw_output='lno1lnd')
        create_offer = Mock(return_value=offer)
        publish = AsyncMock()
        client = self.client_factory(
            transport=httpx.ASGITransport(app=app_module.app),
            base_url='http://testserver', cookies={'csrf_token': 'test'},
        )
        with (
            patch.object(app_module, 'LND_REST_URL', 'https://lnd.test'),
            patch.object(app_module, 'require_pay_auth'),
            patch.object(app_module, '_cloudflare_lookup_txt_records', AsyncMock(return_value=[])),
            patch.object(app_module, '_cloudflare_upsert_txt_record', publish),
            patch.object(app_module, '_create_offer_internal', create_offer),
            patch.object(app_module, 'PUBLIC_BIP353_REPAIR_TASK', None),
            patch.object(app_module, 'PUBLIC_BIP353_REPAIR_JOB', {}),
        ):
            async with client:
                status = (await client.get('/api/setup/public-bip353-status')).json()
                self.assertFalse(status['receiving_wallet_available'])
                self.assertTrue(status['can_recreate_with_lnd'])
                with self.assertRaises(HTTPException) as error:
                    await app_module._repair_public_bip353_record()
                self.assertEqual(error.exception.status_code, 409)
                create_offer.assert_not_called()
                response = await client.post(
                    '/api/setup/public-bip353-repair', headers={'X-CSRF-Token': 'test'},
                    json={'address': address, 'use_lnd': True},
                )
                self.assertEqual(response.status_code, 202)
                await app_module.PUBLIC_BIP353_REPAIR_TASK
                job = (await client.get('/api/setup/public-bip353-repair-status')).json()
                self.assertEqual(job['state'], 'completed')
                self.assertTrue(job['created'])
        self.assertEqual(create_offer.call_args.args[0].description, address)
        self.assertEqual(publish.await_args.kwargs['name'], 'pay.user._bitcoin-payment.wallet.example')
        self.assertEqual(publish.await_args.kwargs['content'], app_module.build_bip353_txt_value(offer.offer))
        updated = config.load_config()
        self.assertEqual(updated['public_receiving_backend_id'], backends.LND_ID)
        self.assertEqual(updated['aliases'], cfg['aliases'])

    async def test_public_bip353_repair_keeps_binding_until_lnd_offer_is_published(self):
        address = 'pay@wallet.example'
        cfg = config.load_config()
        cfg.update(dns_mode='cloudflare', public_bolt12_address=address,
                   public_receiving_backend_id=INSTANCE['id'],
                   cloudflare={'zone_name': 'example', 'zone_id': 'zone', 'api_token': 'token'})
        config.save_config(cfg)
        payload = app_module.PublicBip353RepairRequest(address=address, use_lnd=True)
        lookup = AsyncMock(return_value=[])
        publish = AsyncMock(side_effect=HTTPException(502, 'DNS unavailable'))
        create = AsyncMock(return_value=app_module.OfferResponse(offer='lno1lnd', raw_output='lno1lnd'))
        with (
            patch.object(app_module, '_cloudflare_lookup_txt_records', lookup),
            patch.object(app_module, '_cloudflare_upsert_txt_record', publish),
            patch.object(app_module, '_create_bound_offer', create),
        ):
            self.assertFalse((await app_module._check_public_bip353_record())['can_recreate_with_lnd'])
            with self.assertRaises(HTTPException) as unavailable:
                await app_module._repair_public_bip353_record(payload)
            self.assertEqual(unavailable.exception.status_code, 409)
            create.assert_not_awaited()

            with patch.object(app_module, 'LND_REST_URL', 'https://lnd.test'):
                with self.assertRaises(HTTPException) as failure:
                    await app_module._repair_public_bip353_record(payload)
                self.assertEqual(failure.exception.status_code, 502)
                self.assertEqual(config.load_config()['public_receiving_backend_id'], INSTANCE['id'])
                existing = [{'content': 'bitcoin:?lno=lno1existing'}]
                lookup.side_effect = [[], existing]
                result = await app_module._repair_public_bip353_record(payload)
                self.assertFalse(result['created'])

        publish.assert_awaited_once()
        self.assertEqual(config.load_config()['public_receiving_backend_id'], INSTANCE['id'])

    async def test_first_phoenix_configuration_starts_workers_without_restart(self):
        config.save_config({})
        client = AsyncMock()
        with patch.object(app_module, 'require_pay_auth'), patch.object(backends, 'checked_client', AsyncMock(return_value=(client, NODE))), patch.object(app_module, '_start_wallet_workers') as start:
            await app_module.save_lightning_backend({'active': 'phoenixd', 'url': INSTANCE['url'], 'password': INSTANCE['password']}, request())
        start.assert_called_once()
