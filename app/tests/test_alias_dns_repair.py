"""Read-only upgrade warnings and explicit DNS repair reusing existing offers."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from starlette.requests import Request
from backend import app as backend, config


class AliasDnsRepairTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(config, 'CONFIG_PATH', str(Path(self.tmp.name)/'config.json'))
        patcher.start(); self.addCleanup(patcher.stop)
        self.cfg = {
            'public_bolt12_address': 'bolt12@wallet.example.com',
            'bip353_base_domain': 'wallet.example.com', 'lnurl_base_domain': 'fallback.example.com',
            'dns_mode': 'cloudflare',
            'cloudflare': {'zone_name': 'example.com', 'zone_id': 'parent-zone', 'api_token': 'fixture-token'},
            'lightning_backend': {'active': 'lnd-default', 'phoenixd': None},
            'aliases': {'alice': {'published': True, 'last_offer': 'lno1existing',
                'dns_name': 'alice.user._bitcoin-payment.example.com',
                'backend_id': 'phoenixd-original-wallet', 'amount_sat': 21, 'description': 'Alice'}},
        }
        config.save_config(self.cfg)
        self.canonical = 'alice.user._bitcoin-payment.wallet.example.com'
        self.records = {self.cfg['aliases']['alice']['dns_name']: [{'content': 'lno1existing'}]}
        async def lookup(*, name, **kwargs):
            return self.records.get(name, [])
        async def upsert(*, name, content, **kwargs):
            self.records[name] = [{'content': content}]
            return {'name': name, 'content': content}
        self.lookup = AsyncMock(side_effect=lookup)
        self.upsert = AsyncMock(side_effect=upsert)
        for name, value in [('_cloudflare_lookup_txt_records', self.lookup),
                            ('_cloudflare_upsert_txt_record', self.upsert)]:
            patcher = patch.object(backend, name, value)
            patcher.start(); self.addCleanup(patcher.stop)

    def payload(self, names=None):
        return backend.AliasDnsRepairRequest(revision=backend._alias_dns_revision(config.load_config()),
                                              aliases=names or ['alice'])

    async def test_check_is_read_only_and_marks_canonical_missing_record(self):
        result = await backend._verify_published_bip353_records('aliases')
        self.assertEqual(result['items'][0]['dns_name'], self.canonical)
        self.assertEqual(result['items'][0]['status'], 'missing')
        self.assertTrue(result['items'][0]['needs_update'])
        self.assertTrue(result['items'][0]['repairable'])
        self.upsert.assert_not_awaited()
        self.assertEqual(config.load_config()['aliases'], self.cfg['aliases'])

    async def test_repair_keeps_offer_wallet_amount_and_old_dns(self):
        with (patch.object(backend, '_create_bound_offer', AsyncMock()) as create,
              patch.object(backend, '_cloudflare_delete_txt_record', AsyncMock()) as delete):
            result = await backend._repair_alias_dns_records(self.payload())
        self.assertEqual(result['repaired'], 1)
        self.assertTrue(result['ok'])
        args = self.upsert.call_args.kwargs
        self.assertEqual(args['name'], self.canonical)
        self.assertEqual(args['existing_records'], [])
        self.assertIn('lno1existing', args['content'])
        self.assertEqual(args['cloudflare_config']['zone_id'], 'parent-zone')
        alias = config.load_config()['aliases']['alice']
        for key in ['last_offer', 'backend_id', 'amount_sat', 'description']:
            self.assertEqual(alias[key], self.cfg['aliases']['alice'][key])
        self.assertEqual(alias['dns_name'], self.canonical)
        self.assertIn(self.cfg['aliases']['alice']['dns_name'], self.records)
        create.assert_not_awaited(); delete.assert_not_awaited()
        verified = await backend._verify_published_bip353_records('aliases')
        self.assertEqual(verified['items'][0]['status'], 'present')
        self.assertFalse(verified['items'][0]['needs_update'])

    async def test_different_record_is_never_overwritten(self):
        self.records[self.canonical] = [{'content': 'bitcoin:?lno=lno1someoneelse'}]
        result = await backend._repair_alias_dns_records(self.payload())
        self.assertEqual(result['items'][0]['status'], 'conflict')
        self.assertFalse(result['ok'])
        self.upsert.assert_not_awaited()
        self.assertEqual(config.load_config()['aliases'], self.cfg['aliases'])

    async def test_confirmed_single_conflict_reuses_offer_and_rechecks_records(self):
        self.records[self.canonical] = [{'id': 'reviewed-record', 'content': 'bitcoin:?lno=lno1old'}]
        checked = await backend._verify_published_bip353_records('aliases')
        item = checked['items'][0]
        self.assertFalse(item['repairable'])
        self.assertTrue(item['replaceable'])
        payload = backend.AliasDnsRepairRequest(revision=checked['revision'], aliases=['alice'],
            replace_records={'alice': item['dns_revision']})
        result = await backend._repair_alias_dns_records(payload)
        self.assertEqual(result['repaired'], 1)
        self.assertEqual(self.upsert.call_args.kwargs['existing_records'][0]['id'], 'reviewed-record')
        self.assertIn('lno1existing', self.upsert.call_args.kwargs['content'])
        self.assertEqual(config.load_config()['aliases']['alice']['backend_id'], 'phoenixd-original-wallet')

    async def test_changed_record_after_confirmation_is_not_overwritten(self):
        self.records[self.canonical] = [{'id': 'reviewed-record', 'content': 'bitcoin:?lno=lno1old'}]
        checked = await backend._verify_published_bip353_records('aliases')
        payload = backend.AliasDnsRepairRequest(revision=checked['revision'], aliases=['alice'],
            replace_records={'alice': checked['items'][0]['dns_revision']})
        self.records[self.canonical][0]['content'] = 'bitcoin:?lno=lno1changedexternally'
        result = await backend._repair_alias_dns_records(payload)
        self.assertEqual(result['items'][0]['status'], 'conflict')
        self.upsert.assert_not_awaited()

    async def test_non_bip353_and_multiple_records_cannot_be_replaced(self):
        for records in ([{'id': 'unrelated', 'content': 'verification=unrelated'}],
                        [{'id': 'one', 'content': 'bitcoin:?lno=lno1old'},
                         {'id': 'two', 'content': 'bitcoin:?lno=lno1another'}]):
            with self.subTest(records=records):
                self.records[self.canonical] = records
                checked = await backend._verify_published_bip353_records('aliases')
                self.assertFalse(checked['items'][0]['replaceable'])
                payload = backend.AliasDnsRepairRequest(revision=checked['revision'], aliases=['alice'],
                    replace_records={'alice': checked['items'][0]['dns_revision']})
                result = await backend._repair_alias_dns_records(payload)
                self.assertEqual(result['items'][0]['status'], 'conflict')
        self.upsert.assert_not_awaited()

    async def test_stale_plan_rejected_before_dns_write(self):
        payload = self.payload()
        self.cfg['aliases']['alice']['last_offer'] = 'lno1changed'
        config.save_config(self.cfg)
        with self.assertRaises(HTTPException) as error:
            await backend._repair_alias_dns_records(payload)
        self.assertEqual(error.exception.status_code, 409)
        self.lookup.assert_not_awaited(); self.upsert.assert_not_awaited()

    async def test_alias_changed_during_lookup_is_not_published(self):
        async def change_during_lookup(**kwargs):
            changed = config.load_config()
            changed['aliases']['alice']['last_offer'] = 'lno1changed'
            config.save_config(changed)
            return []
        self.lookup.side_effect = change_during_lookup
        result = await backend._repair_alias_dns_records(self.payload())
        self.assertEqual(result['items'][0]['status'], 'conflict')
        self.upsert.assert_not_awaited()

    async def test_matching_record_only_updates_saved_name_and_can_be_checked_again(self):
        self.records[self.canonical] = [{'content': 'bitcoin:?lno=lno1existing'}]
        await backend._repair_alias_dns_records(self.payload())
        result = await backend._repair_alias_dns_records(self.payload())
        self.assertEqual(result['items'][0]['status'], 'already_present')
        self.upsert.assert_not_awaited()

    async def test_one_provider_failure_does_not_hide_other_results(self):
        self.cfg['aliases']['bob'] = copy.deepcopy(self.cfg['aliases']['alice'])
        config.save_config(self.cfg)
        lookup = self.lookup.side_effect
        async def partial(**kwargs):
            if kwargs['name'].startswith('bob.'):
                raise HTTPException(502, 'provider unavailable')
            return await lookup(**kwargs)
        self.lookup.side_effect = partial
        result = await backend._repair_alias_dns_records(self.payload(['alice', 'bob']))
        self.assertEqual(result['repaired'], 1)
        self.assertEqual(result['failed'], 1)

    async def test_draft_or_missing_alias_offer_is_not_repaired(self):
        self.cfg['aliases']['alice']['published'] = False
        config.save_config(self.cfg)
        with self.assertRaises(HTTPException):
            await backend._repair_alias_dns_records(self.payload())
        self.upsert.assert_not_awaited()

    async def test_route_requires_authentication_and_csrf(self):
        req = Request({'type': 'http', 'headers': []})
        with patch.object(backend, 'require_pay_auth', side_effect=HTTPException(401)):
            with self.assertRaises(HTTPException) as error:
                await backend.repair_alias_dns_records(self.payload(), req)
            self.assertEqual(error.exception.status_code, 401)
        with patch.object(backend, 'require_pay_auth'):
            with self.assertRaises(HTTPException) as error:
                await backend.repair_alias_dns_records(self.payload(), req)
            self.assertEqual(error.exception.status_code, 403)
        self.upsert.assert_not_awaited()
