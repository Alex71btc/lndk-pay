"""First real NWC setup must work without a personal nsec or an LND signer."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from starlette.requests import Request

from backend import app as backend, config, nwc


class NwcKeyBootstrapTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.secret_path = self.root / 'config/secrets.json'
        self.instance = {'id': 'phoenixd-test', 'node_id': '02' + '11' * 32}
        for target, name, value in (
            (backend, 'CONFIG_DIR', self.root / 'config'),
            (backend, 'CONFIG_JSON_PATH', self.root / 'config.json'),
            (backend, 'SECRETS_JSON_PATH', self.secret_path),
            (backend, 'LND_REST_URL', ''),
            (backend, 'NOSTR_SECRET_STORE_KEY', None),
            (backend, 'NOSTR_SECRET_STORE_STATUS', {'state': 'starting', 'encrypted': False}),
            (config, 'CONFIG_PATH', str(self.root / 'config.json')),
            (nwc, 'NWC_CONNECTIONS_PATH', self.root / 'config/nwc_connections.json'),
        ):
            p = patch.object(target, name, value)
            p.start(); self.addCleanup(p.stop)
        p = patch.dict('os.environ', {'NOSTR_SERVER_PRIVKEY': '', 'NOSTR_NOTIFY_NSEC': ''})
        p.start(); self.addCleanup(p.stop)
        config.save_config({'lightning_backend': {'active': self.instance['id'], 'phoenixd': self.instance}})
        self.request = Request({'type': 'http', 'headers': []})

    async def create(self):
        with (patch.object(backend, 'require_pay_auth'), patch.object(backend, 'require_nwc_auth'),
              patch.object(backend, 'reload_nwc_runtime', AsyncMock())):
            return await backend.api_admin_nwc_connections_create(
                backend.NwcConnectionCreateRequest(backend_id=self.instance['id'], name='Phoenix test',
                    max_payment_sat=100, budget_amount_sat=50), self.request)

    async def test_first_connection_creates_encrypted_signer_without_profile_nsec_or_lnd(self):
        with patch.object(backend, '_request_lnd_nostr_shared_key', side_effect=AssertionError('LND accessed')):
            response = await self.create()
        connection = response['connection']
        self.assertTrue(response['ok'])
        self.assertEqual(connection['backend_id'], self.instance['id'])
        self.assertTrue(connection['uri'].startswith('nostr+walletconnect://'))
        values = backend.load_secrets()
        self.assertTrue(values['nostr_server_privkey'])
        self.assertNotIn('nostr_notify_nsec', values)
        raw = json.loads(self.secret_path.read_text())
        self.assertEqual(raw['_encryption']['provider'], 'local-file-v1')
        self.assertNotIn(values['nostr_server_privkey'], self.secret_path.read_text())
        self.assertEqual((self.root / 'config/nostr-master.key').stat().st_mode & 0o777, 0o600)
        self.assertEqual(backend._get_nostr_admin_status()['secret_store']['provider'], 'local-file-v1')

    async def test_restart_and_second_connection_reuse_same_signer(self):
        first = await self.create()
        backend.NOSTR_SECRET_STORE_KEY = None
        second = await self.create()
        self.assertEqual(first['connection']['wallet_service_pubkey'], second['connection']['wallet_service_pubkey'])
        self.assertEqual(len(nwc.list_nwc_connections()), 2)

    async def test_simultaneous_first_connections_share_one_signer(self):
        first, second = await asyncio.gather(self.create(), self.create())
        self.assertEqual(first['connection']['wallet_service_pubkey'], second['connection']['wallet_service_pubkey'])

    async def initialize_lnd_store(self, values=None):
        with (patch.object(backend, 'LND_REST_URL', 'http://lnd-test'),
              patch.object(backend, '_request_lnd_nostr_shared_key', AsyncMock(return_value=b'x' * 32))):
            await backend._unlock_nostr_secret_store_once()
            if values:
                backend.save_secrets(values)
        backend.NOSTR_SECRET_STORE_KEY = None

    async def test_empty_old_lnd_envelope_does_not_block_standalone_setup(self):
        await self.initialize_lnd_store()
        with patch.object(backend, '_request_lnd_nostr_shared_key', side_effect=AssertionError('LND accessed')):
            await self.create()
        self.assertEqual(json.loads(self.secret_path.read_text())['_encryption']['provider'], 'local-file-v1')

    async def test_nonempty_lnd_store_is_preserved_and_explained(self):
        for field in backend.NOSTR_SECRET_FIELDS:
            with self.subTest(field=field):
                self.secret_path.unlink(missing_ok=True)
                backend.NOSTR_SECRET_STORE_KEY = None
                await self.initialize_lnd_store({field: '01' * 32})
                before = self.secret_path.read_bytes()
                with self.assertRaises(HTTPException) as error:
                    await self.create()
                self.assertEqual(error.exception.status_code, 503)
                self.assertIn('original LND', error.exception.detail)
                self.assertEqual(self.secret_path.read_bytes(), before)
                self.assertFalse((self.root / 'config/nostr-master.key').exists())
                self.assertEqual(nwc.list_nwc_connections(), [])

    async def test_existing_local_key_missing_fails_without_reset(self):
        await self.create()
        before = self.secret_path.read_bytes()
        (self.root / 'config/nostr-master.key').unlink()
        backend.NOSTR_SECRET_STORE_KEY = None
        with self.assertRaises(HTTPException) as error:
            await self.create()
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(self.secret_path.read_bytes(), before)
        self.assertEqual(len(nwc.list_nwc_connections()), 1)

    async def test_authentication_and_stale_backend_precede_key_generation(self):
        payload = backend.NwcConnectionCreateRequest(backend_id='lnd-default')
        with patch.object(backend, 'require_pay_auth', side_effect=HTTPException(401)):
            with self.assertRaises(HTTPException) as error:
                await backend.api_admin_nwc_connections_create(payload, self.request)
            self.assertEqual(error.exception.status_code, 401)
        with (patch.object(backend, 'require_pay_auth'), patch.object(backend, 'require_nwc_auth')):
            with self.assertRaises(HTTPException) as error:
                await backend.api_admin_nwc_connections_create(payload, self.request)
            self.assertEqual(error.exception.status_code, 409)
        self.assertFalse(self.secret_path.exists())

    async def test_existing_environment_signer_is_kept(self):
        with patch.dict('os.environ', {'NOSTR_SERVER_PRIVKEY': '01' * 32}):
            expected = backend._nostr_server_pubkey_hex()
            response = await self.create()
        self.assertEqual(response['connection']['wallet_service_pubkey'], expected)
        self.assertFalse(self.secret_path.exists())

    async def test_existing_lnd_signer_is_reused_after_unlock(self):
        await self.initialize_lnd_store({'nostr_server_privkey': '01' * 32,
                                         'nostr_notify_nsec': 'existing-profile-secret'})
        with (patch.object(backend, 'LND_REST_URL', 'http://lnd-test'),
              patch.object(backend, '_request_lnd_nostr_shared_key', AsyncMock(return_value=b'x' * 32)),
              patch.object(backend, '_generate_nostr_private_key_hex', side_effect=AssertionError('Key replaced'))):
            await self.create()
        self.assertEqual(backend.load_secrets()['nostr_server_privkey'], '01' * 32)
        self.assertEqual(backend.load_secrets()['nostr_notify_nsec'], 'existing-profile-secret')
        self.assertEqual(json.loads(self.secret_path.read_text())['_encryption']['provider'], 'lnd-ecdh-v1')
