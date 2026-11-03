"""Exercise the public HTTP routes and the shipped invoice UI without a wallet."""

import json
import re
import subprocess
import unittest
from contextlib import ExitStack
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import httpx
from backend import app as backend


APP = Path(__file__).resolve().parents[1]


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.by_id = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = dict(attrs)
        self.tags.append((tag, node))
        if "id" in node:
            self.by_id[node["id"]] = node


class PublicPageI18nTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = {"aliases": {"alice": {
            "description": 'User text <em>untranslated</em> & "unchanged"',
            "amount_sat": 21, "last_offer": "lno1test",
        }}}
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        for name, value in {
            "load_config": self.config, "privacy_mode_enabled": False,
            "get_public_bolt12_address": "store@bip.example",
            "get_bip353_base_domain": "bip.example", "get_lnurl_base_domain": "ln.example",
            "_build_lnurl_info_for_address": {"lnurl": "LNURL1TEST"},
        }.items():
            self.patches.enter_context(patch.object(backend, name, return_value=value))

    async def get(self, path):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=backend.app), base_url="http://test"
        ) as client:
            return await client.get(path)

    def check_catalog(self, response, scope):
        html = response.text
        page = Elements(html)
        sources = [node["src"] for tag, node in page.tags if tag == "script" and "src" in node]
        self.assertEqual(sources, ["/assets/i18n/runtime.js", f"/assets/i18n/{scope}.js"])
        self.assertIn(f'window.Bolt12I18n.use("{scope}")', html.split("</head>")[0])
        self.assertTrue(any("data-i18n-language" in node for _, node in page.tags))
        for language in ("en", "de", "es", "fr", "pl"):
            catalog = json.loads((APP / "i18n" / scope / f"{language}.json").read_text())
            for _, node in page.tags:
                for attr in ("data-i18n", "data-i18n-placeholder", "data-i18n-alt",
                             "data-i18n-title", "data-i18n-aria-label"):
                    if attr in node:
                        self.assertIn(node[attr], catalog, f"{scope}/{language}")
        return page

    async def test_landing_and_links_keep_user_data_and_alias_actions(self):
        for route in ("/", "/links"):
            response = await self.get(route)
            self.assertEqual(response.status_code, 200)
            page = self.check_catalog(response, "landing")
            self.assertIn("User text &lt;em&gt;untranslated&lt;/em&gt;", response.text)
            self.assertNotIn("<em>untranslated</em>", response.text)
            self.assertTrue(any(node.get("data-alias-path") == "/alias/alice" for _, node in page.tags))
            self.assertTrue(any(node.get("data-copy-address") == "alice@bip.example" for _, node in page.tags))
            amount = next(node for _, node in page.tags if node.get("data-i18n") == "amount.fixed")
            self.assertEqual(json.loads(amount["data-i18n-params"]), {"amount": 21})

    async def test_empty_landing_and_missing_alias_use_their_catalogs(self):
        self.config["aliases"].clear()
        landing = await self.get("/")
        self.assertIn('data-i18n="alias.empty"', landing.text)
        for route in ("/alias/missing", "/alias/bad%20name"):
            response = await self.get(route)
            self.assertEqual(response.status_code, 404)
            self.check_catalog(response, "alias")
            self.assertIn('data-i18n="error.not_found"', response.text)

    async def test_compatibility_routes_preserve_wallet_and_qr_values(self):
        response = await self.get("/alias/alice")
        self.assertEqual(response.status_code, 200)
        page = self.check_catalog(response, "alias")
        self.assertIn("User text &lt;em&gt;untranslated&lt;/em&gt;", response.text)
        for element, target in {
            "aliasOpenWalletBtn": "alice@bip.example",
            "aliasLnurlWalletBtn": "alice@ln.example", "aliasOfferWalletBtn": "lno1test",
        }.items():
            self.assertEqual(page.by_id[element]["data-wallet-target"], target)
            self.assertIn("'lightning:'+this.dataset.walletTarget", page.by_id[element]["onclick"])
        for element, value in {"aliasOfferQr": "lno1test", "aliasBip353Qr": "alice@bip.example",
                               "aliasLnurlQr": "LNURL1TEST"}.items():
            self.assertEqual(page.by_id[element]["src"], "/api/qr/" + value)
        self.assertEqual(page.by_id["aliasLnurlQr"]["data-copy-target"], "LNURL1TEST")
        self.assertEqual(page.by_id["aliasSubline"]["data-i18n"], "page.subline")
        self.assertNotIn("aliasBolt11AmountInput", page.by_id)

    async def test_private_page_has_no_fallback_methods_and_localizes_default_values(self):
        self.config["aliases"]["alice"].update(description="", amount_sat=None, last_offer="")
        with patch.object(backend, "privacy_mode_enabled", return_value=True):
            response = await self.get("/alias/alice")
        page = self.check_catalog(response, "alias")
        self.assertEqual(page.by_id["aliasSubline"]["data-i18n"], "page.private_subline")
        self.assertIn('data-i18n="amount.variable"', response.text)
        self.assertIn('data-i18n="payment.default_description"', response.text)
        for element in ("aliasLnurlQr", "aliasOfferQr", "aliasGenerateBolt11Btn", "aliasBolt11AmountInput"):
            self.assertNotIn(element, page.by_id)

    async def test_invoice_language_switch_preserves_pending_request_and_result(self):
        self.config["aliases"]["alice"]["amount_sat"] = None
        response = await self.get("/alias/alice")
        scripts = re.findall(r"<script>(.*?)</script>", response.text, flags=re.S)
        body_script = next(script for script in scripts if "function generateBolt11Fallback" in script)
        wallet_script = next(script for script in scripts if "function payBolt11Invoice" in script)
        fixture = """
const assert = require('node:assert/strict');
const nodes = new Map();
const loadCallbacks = [];
const requests = [], payments = [];
let completeRequest;
const window = {
  __t: key => 'en:' + key,
  addEventListener(name, cb) { if (name === 'load') loadCallbacks.push(cb); },
  webln: { enable: async () => {}, sendPayment: async invoice => payments.push(invoice) }
};
const document = {getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, {dataset: {}, style: {}, focus() {}});
  return nodes.get(id);
}};
const fetch = (path, options) => {
  requests.push([path, options]);
  return new Promise(resolve => completeRequest = resolve);
};
const setTimeout = () => 1, clearTimeout = () => {};
"""
        scenario = """
(async () => {
  loadCallbacks.forEach(cb => cb());
  assert.equal(requests.length, 0);
  const button = nodes.get('aliasGenerateBolt11Btn');
  const amount = document.getElementById('aliasBolt11AmountInput');
  amount.value = '0';
  await button.onclick();
  assert.equal(requests.length, 0);
  assert.equal(nodes.get('aliasToast').dataset.i18n, 'error.amount_required');
  amount.value = '21';
  const pending = button.onclick();
  assert.equal(button.disabled, true);
  assert.equal(button.dataset.i18n, 'invoice.generating');
  assert.equal(requests.length, 1);
  assert.equal(requests[0][0], '/api/alias/alice/bolt11-fallback');
  assert.equal(requests[0][1].method, 'POST');
  assert.deepEqual(JSON.parse(requests[0][1].body), {amount_sat: 21});
  window.__t = key => 'pl:' + key;
  completeRequest({ok: true, text: async () => '{"payment_request":"lnbc1test"}'});
  await pending;
  assert.equal(button.disabled, false);
  assert.equal(button.textContent, 'pl:invoice.generate');
  assert.equal(nodes.get('aliasToast').textContent, 'pl:toast.invoice_created');
  assert.equal(nodes.get('aliasBolt11String').textContent, 'lnbc1test');
  assert.equal(nodes.get('aliasBolt11Qr').src, '/api/qr/lnbc1test');
  assert.equal(payments.length, 0);
  await nodes.get('aliasBolt11WalletBtn').onclick();
  assert.deepEqual(payments, ['lnbc1test']);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(["node", "-"], input="\n".join((fixture, wallet_script, body_script, scenario)),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
