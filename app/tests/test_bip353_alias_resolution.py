"""Alias DNS uses the advertised domain; explicit LNURL never masks BIP353."""
import unittest
from unittest.mock import AsyncMock, patch

import dns.rdata
import dns.rdataclass
import dns.rdatatype
from backend import app as backend


class AliasDnsTests(unittest.TestCase):
    def test_old_alias_reports_expected_dns_name_and_republication_warning(self):
        with (
            patch.object(backend, 'get_cloudflare_config', return_value={'zone_name': 'example.com'}),
            patch.object(backend, 'get_bip353_base_domain', return_value='wallet.example.com'),
            patch.object(backend, 'get_lnurl_base_domain', return_value='wallet.example.com'),
        ):
            alias = {'published': True, 'dns_name': 'alice.user._bitcoin-payment.example.com'}
            response = backend._build_alias_response('alice', alias)
            self.assertTrue(response['dns_needs_republish'])
            self.assertEqual(response['expected_dns_name'], 'alice.user._bitcoin-payment.wallet.example.com')
            self.assertEqual(alias['dns_name'], 'alice.user._bitcoin-payment.example.com', 'Reading does not rewrite DNS')
            alias['dns_name'] = response['expected_dns_name']
            self.assertFalse(backend._build_alias_response('alice', alias)['dns_needs_republish'])

    def test_alias_dns_matches_bip353_domain_not_parent_zone_or_lnurl_domain(self):
        with (
            patch.object(backend, 'get_cloudflare_config', return_value={'zone_name': 'example.com'}),
            patch.object(backend, 'get_bip353_base_domain', return_value='wallet.example.com'),
            patch.object(backend, 'get_lnurl_base_domain', return_value='lnurl.example.com'),
        ):
            self.assertEqual(backend._alias_dns_name('alice'),
                             'alice.user._bitcoin-payment.wallet.example.com')

    def test_manager_distinguishes_root_bip353_and_lnurl_subdomain(self):
        with (
            patch.object(backend, 'get_cloudflare_config', return_value={'zone_name': 'example.com'}),
            patch.object(backend, 'get_bip353_base_domain', return_value='example.com'),
            patch.object(backend, 'get_lnurl_base_domain', return_value='startos.example.com'),
            patch.object(backend, 'privacy_mode_enabled', return_value=False),
        ):
            response = backend._build_alias_response('alice', {
                'published': True, 'dns_name': 'alice.user._bitcoin-payment.example.com',
            })
        self.assertEqual(response['bip353_address'], 'alice@example.com')
        self.assertEqual(response['lnurl_address'], 'alice@startos.example.com')
        self.assertEqual(response['expected_dns_name'], 'alice.user._bitcoin-payment.example.com')
        self.assertFalse(response['dns_needs_republish'], 'Different fallback domain is intentional')

    def test_verification_checks_canonical_name_even_when_old_name_was_saved(self):
        with (
            patch.object(backend, 'get_cloudflare_config', return_value={'zone_name': 'example.com'}),
            patch.object(backend, 'get_bip353_base_domain', return_value='wallet.example.com'),
            patch.object(backend, 'get_lnurl_base_domain', return_value='wallet.example.com'),
        ):
            entries = backend._published_bip353_verification_entries({'aliases': {'alice': {
                'published': True, 'dns_name': 'alice.user._bitcoin-payment.example.com',
                'last_offer': 'lno1offer',
            }}}, 'aliases')
        self.assertEqual(entries[0]['dns_name'], 'alice.user._bitcoin-payment.wallet.example.com')
        self.assertEqual(entries[0]['address'], 'alice@wallet.example.com')


class ExplicitAliasResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_lnurl_alias_does_not_hide_long_multistring_bip353_offer(self):
        offer = 'lno1' + 'qpzry9x8' * 220
        txt = 'bitcoin:?lno=' + offer
        # DNS TXT values are split into character strings of at most 255 bytes.
        record = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                    ' '.join('"' + txt[i:i+255] + '"' for i in range(0, len(txt), 255)))
        resolver = unittest.mock.Mock()
        resolver.resolve.return_value = [record]

        async def inline(function, *args):
            return function(*args)

        with (
            patch.object(backend.asyncio, 'to_thread', inline),
            patch.object(backend, '_new_resolver', return_value=resolver),
            patch.object(backend, '_fetch_lnurl_metadata_from_url', AsyncMock(return_value={
                'callback': 'https://wallet.example.com/api/lnurl/callback/alice',
                'minSendable': 21000, 'maxSendable': 21000,
                'metadata': '[["text/identifier","alice@wallet.example.com"]]',
            })),
        ):
            result = await backend._resolve_pay_address_methods('alice@wallet.example.com')
        self.assertEqual(result['available_methods'], ['bolt12', 'lnurl'])
        self.assertEqual(result['bolt12']['resolved_offer'], offer)
        self.assertEqual(result['lnurl']['min_sat'], 21)
        self.assertEqual(result['lnurl']['max_sat'], 21)
        resolver.resolve.assert_called_once_with('alice.user._bitcoin-payment.wallet.example.com', 'TXT')
