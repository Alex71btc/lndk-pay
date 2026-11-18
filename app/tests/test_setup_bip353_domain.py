"""Setup explicitly separates shared BIP353 naming from the LNURL fallback."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from backend import app as backend, config


class Bip353SetupValidationTests(unittest.TestCase):
    def test_old_clients_derive_the_shared_domain_from_the_public_address(self):
        self.assertEqual(backend._bip353_setup_address_domain({
            'public_bolt12_address': ' Merchant@Example.com ',
        }), ('merchant@example.com', 'example.com'))

    def test_explicit_domain_and_address_are_consistent(self):
        self.assertEqual(backend._bip353_setup_address_domain({
            'public_bolt12_address': 'merchant@wallet.example.com',
            'bip353_base_domain': 'WALLET.EXAMPLE.COM.',
        }), ('merchant@wallet.example.com', 'wallet.example.com'))

    def test_rejects_address_mismatch_or_url_port_path_as_domain(self):
        for domain in ['other.example.com', '', 'https://example.com',
                       'example.com:443', 'example.com/path', '-bad.example.com']:
            with self.subTest(domain=domain), self.assertRaises(HTTPException):
                backend._bip353_setup_address_domain({
                    'public_bolt12_address': 'merchant@example.com',
                    'bip353_base_domain': domain,
                })


class Bip353SetupSaveTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_save_preserves_aliases_and_separate_fallback_domain(self):
        with tempfile.TemporaryDirectory() as root, patch.object(config, 'CONFIG_PATH', str(Path(root)/'config.json')):
            aliases = {'coffee': {'published': True, 'last_offer': 'lno1existing',
                                 'dns_name': 'coffee.user._bitcoin-payment.example.com'}}
            config.save_config({'public_bolt12_address': 'merchant@example.com', 'aliases': aliases})
            with patch.object(backend, '_is_pay_ui_enabled', return_value=False):
                await backend.set_setup_config({
                    'public_bolt12_address': 'merchant@example.com',
                    'lnurl_base_domain': 'startos.example.com',
                    'lnurl_base_url': 'https://startos.example.com',
                    'dns_mode': 'none',
                    'cloudflare': {'zone_name': 'example.com', 'zone_id': 'parent-zone'},
                }, object())
            saved = config.load_config()
            self.assertEqual(saved['bip353_base_domain'], 'example.com')
            self.assertEqual(saved['lnurl_base_domain'], 'startos.example.com')
            self.assertEqual(saved['aliases'], aliases)
            self.assertEqual(saved['cloudflare']['zone_id'], 'parent-zone')
            self.assertEqual(backend._alias_dns_name('coffee'), 'coffee.user._bitcoin-payment.example.com')

    async def test_mismatch_fails_before_dns_or_config_is_changed(self):
        with (patch.object(backend, '_is_pay_ui_enabled', return_value=False),
              patch.object(backend, 'load_config', return_value={}),
              patch.object(backend, 'save_config') as save,
              patch.object(backend, '_cloudflare_lookup_txt_records', AsyncMock()) as dns):
            with self.assertRaises(HTTPException) as error:
                await backend.set_setup_config({
                    'public_bolt12_address': 'merchant@wrong.example.com',
                    'bip353_base_domain': 'example.com', 'dns_mode': 'cloudflare',
                }, object())
        self.assertEqual(error.exception.status_code, 400)
        save.assert_not_called()
        dns.assert_not_awaited()


class Bip353SetupUiTests(unittest.TestCase):
    def test_domain_edit_updates_standard_address_and_dns_example_but_not_lnurl(self):
        html = (Path(__file__).resolve().parents[1]/'frontend/public/index.html').read_text()
        functions = html[html.index('    function loadBip353SetupFields('):html.index('    function updatePaymentModeUi(')]
        script = r'''
const assert=require('node:assert/strict');
const field=(value='')=>({value,setCustomValidity(value){this.validity=value;}});
const setupBolt12Address=field(),setupBip353Domain=field();
const setupLnurlBaseDomain=field('startos.example.com');
const setupBip353Examples={},setupBip353Mismatch={};
const manualDnsExampleName={},manualDnsHint={},cloudflareFields={};
const setupDnsMode=field('manual');
let loadedSetupBolt12Address='';
const window={__t:(key,params)=>key+':'+JSON.stringify(params)};
const setLabel=(node,key,params)=>{node.textContent=window.__t(key,params);};
'''+functions+r'''
const legacy={public_bolt12_address:'merchant@example.com'};
loadBip353SetupFields(legacy);
assert.equal(setupBip353Domain.value,'example.com');
assert.equal(setupBolt12Address.value,'merchant@example.com');
assert.equal(manualDnsExampleName.textContent,'merchant.user._bitcoin-payment.example.com');
assert.equal(setupBip353Mismatch.hidden,true);
setupBip353Domain.value='wallet.example.com';updateBip353SetupUi(true);
assert.equal(setupBolt12Address.value,'merchant@wallet.example.com');
assert.equal(setupLnurlBaseDomain.value,'startos.example.com');
assert.equal(manualDnsExampleName.textContent,'merchant.user._bitcoin-payment.wallet.example.com');
assert.ok(setupBip353Examples.textContent.includes('wallet.example.com'));
setupBolt12Address.value='newname@wrong.example.com';updateBip353SetupUi();
assert.equal(setupBip353Mismatch.hidden,false);
assert.ok(setupBolt12Address.validity.includes('wallet.example.com'));
setupBolt12Address.value='newname@wallet.example.com';updateBip353SetupUi();
assert.equal(setupBip353Mismatch.hidden,true);
assert.equal(setupBolt12Address.validity,'');
assert.equal(legacy.public_bolt12_address,'merchant@example.com','Editing does not save or publish');
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
