"""Admin pages ship a nonce CSP, and Activity rows never turn wallet data into markup."""

import json
import re
import subprocess
import unittest
from contextlib import ExitStack
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import app as backend, config


APP = Path(__file__).resolve().parents[1]
PAY_PAGE = APP / "frontend/admin/index.html"
ADMIN_PAGES = (PAY_PAGE, APP / "frontend/public/index.html", APP / "frontend/admin/pay-login.html")
PASSWORD = "test-owner-password"
PAYLOAD = '</pre></code><img src=x onerror="alert(1)"><script>alert(2)</script>"\'&'


class TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, tuple(sorted(name for name, _ in attrs))))

    def handle_data(self, data):
        self.text.append(data)


def parse(html):
    collector = TagCollector()
    collector.feed(html)
    collector.close()
    return collector.tags, "".join(collector.text)


class AdminPageCspTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        data_dir = Path(stack.enter_context(TemporaryDirectory()))
        stack.enter_context(patch.object(config, "CONFIG_PATH", str(data_dir / "config.json")))
        stack.enter_context(patch.multiple(
            backend, PAY_UI_PASSWORD="", PAY_SESSIONS={}, NWC_SESSIONS={},
            _LOGIN_FAILURES={}, _LOGIN_LOCKOUTS={}, LOGIN_FAILURE_DELAY_MS=0,
        ))
        config.initialize_ui_password(PASSWORD)
        self.client = TestClient(backend.app, base_url="https://testserver")
        self.addCleanup(self.client.close)

    def assert_nonce_policy(self, response):
        self.assertEqual(response.status_code, 200)
        policy = response.headers["content-security-policy"]
        nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]+)'", policy).group(1)
        script_policy = re.search(r"script-src [^;]*", policy).group()
        self.assertNotIn("unsafe", script_policy)
        for directive in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
            self.assertIn(directive, policy)
        tags = re.findall(r"<script\b[^>]*>", response.text, re.I)
        self.assertTrue(tags)
        for tag in tags:
            self.assertIn(f'nonce="{nonce}"', tag)
        return nonce

    def test_login_console_and_pay_pages_carry_a_fresh_nonce(self):
        first = self.assert_nonce_policy(self.client.get("/pay-login"))
        second = self.assert_nonce_policy(self.client.get("/pay-login"))
        self.assertNotEqual(first, second)
        self.assertEqual(self.client.post("/api/auth/login", json={"password": PASSWORD}).status_code, 200)
        self.assert_nonce_policy(self.client.get("/pay"))
        self.assert_nonce_policy(self.client.get("/app"))

    def test_pages_reissue_a_missing_csrf_cookie(self):
        self.assertEqual(self.client.post("/api/auth/login", json={"password": PASSWORD}).status_code, 200)
        self.client.cookies.delete("csrf_token")
        response = self.client.get("/pay")
        self.assertIn("csrf_token=", response.headers.get("set-cookie", ""))

    def test_pages_have_no_inline_event_handlers_or_javascript_urls(self):
        for page in ADMIN_PAGES:
            html = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                self.assertIsNone(re.search(r"<[^>]+\son[a-z]+\s*=", html))
                self.assertNotIn("javascript:", html.lower())

    def test_third_party_scripts_are_pinned_with_subresource_integrity(self):
        for page in ADMIN_PAGES:
            for tag in re.findall(r"<script\b[^>]*\bsrc=\"https://[^>]*>", page.read_text(encoding="utf-8")):
                with self.subTest(page=page.name, tag=tag):
                    self.assertRegex(tag, r'integrity="sha384-[A-Za-z0-9+/=]+"')
                    self.assertIn('crossorigin="anonymous"', tag)


class ActivityRowRenderingTests(unittest.TestCase):
    """Render real Activity rows in Node and parse the produced markup."""

    def render(self, items):
        html = PAY_PAGE.read_text(encoding="utf-8")
        escape = re.search(r"^      function escapeContactHtml\(value\) \{.*?^      \}", html, re.M | re.S).group()
        start = html.index("      function renderTxHistoryItems(items) {")
        stop = html.index("      let txHistoryRefreshTimer = null;", start)
        script = r"""
const rows = [];
const list = {innerHTML: '', querySelectorAll: () => [], appendChild: (row) => rows.push(row.innerHTML)};
const document = {
  getElementById: (id) => id === 'txHistoryList' ? list : {style: {}},
  createElement: () => ({innerHTML: '', querySelector: () => null}),
};
const window = {__t: (key, values) => key + (values ? JSON.stringify(values) : '')};
let txHistoryHasMore = false;
const loadedContacts = [];
const formatTxTimestamp = (item) => ({iso: String(item.created_at), text: String(item.created_at)});
const plainSatsValue = (value) => String(value);
const detectClipboardPaymentTarget = () => null;
console.time = console.timeEnd = () => {};
""" + escape + "\n" + html[start:stop] + """
renderTxHistoryItems(JSON.parse(require('node:fs').readFileSync(0, 'utf8')));
process.stdout.write(JSON.stringify(rows));
"""
        result = subprocess.run(
            ["node", "-e", script], input=json.dumps(items), text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def item(text):
        fields = (
            "memo", "payer_note", "counterparty", "identifier", "status", "type",
            "fee_sat", "created_at",
        )
        item = {field: text for field in fields}
        item.update({
            "direction": "incoming", "method": "nwc", "origin": "nwc",
            "amount_sat": 21, "payment_hash": text,
            "raw_json": {
                "memo": text, "payment_request": text, "payment_preimage": text, "target": text,
            },
        })
        return item

    def test_markup_in_history_items_renders_as_text_only(self):
        benign, hostile = self.render([self.item("plain-text"), self.item(PAYLOAD)])
        benign_tags, _ = parse(benign)
        hostile_tags, hostile_text = parse(hostile)
        self.assertEqual(hostile_tags, benign_tags, "markup in wallet data added or changed elements")
        self.assertNotIn("script", {tag for tag, _ in hostile_tags})
        self.assertFalse(any("onerror" in attrs for _, attrs in hostile_tags))
        # The raw JSON block still shows the payload, as text.
        self.assertIn(json.dumps(PAYLOAD)[1:-1], hostile_text)


if __name__ == "__main__":
    unittest.main()
