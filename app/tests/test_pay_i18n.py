"""Exercise the real /pay language-change handlers without a server or wallet."""

import json
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


APP = Path(__file__).resolve().parents[1]


class PageScripts(HTMLParser):
    def __init__(self, assets):
        super().__init__()
        self.assets = assets
        self.tags = []
        self.scripts = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = {k: v or "" for k, v in attrs}
        if tag == "script":
            source = attrs.get("src", "")
            self.in_script = not source
            if source.startswith("/assets/i18n/"):
                self.scripts.append((self.assets / source.removeprefix("/assets/")).read_text(encoding="utf-8"))
        else:
            self.tags.append(attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)


class PayLanguageChangeTests(unittest.TestCase):
    def test_switching_language_preserves_inputs_offer_and_request_count(self):
        parser = PageScripts(APP / "assets")
        parser.feed((APP / "frontend/admin/index.html").read_text(encoding="utf-8"))
        runner = Path(__file__).with_name("pay_language_switch.cjs")
        completed = subprocess.run(
            ["node", str(runner)], input=json.dumps({"tags": parser.tags, "scripts": parser.scripts}),
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
