"""Exercise the shipped Console scripts, including language switches while editing."""

import json
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


APP = Path(__file__).resolve().parents[1]


class ConsolePage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.scripts = []
        self.script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            if attrs.get("src"):
                self.scripts.append({"src": attrs["src"]})
            else:
                self.script = []
        else:
            self.tags.append(attrs)

    def handle_data(self, data):
        if self.script is not None:
            self.script.append(data)

    def handle_endtag(self, name):
        if name == "script" and self.script is not None:
            self.scripts.append({"code": "".join(self.script)})
            self.script = None


class ConsoleI18nTests(unittest.TestCase):
    def test_switch_preserves_setup_editing_qr_and_pending_requests(self):
        page = ConsolePage()
        page.feed((APP / "frontend/public/index.html").read_text())
        scripts = []
        for script in page.scripts:
            if "code" in script:
                scripts.append(script["code"])
            elif script["src"].startswith("/assets/i18n/"):
                scripts.append((APP / script["src"].lstrip("/")).read_text())
        result = subprocess.run(
            ["node", str(Path(__file__).with_name("console_language_switch.cjs"))],
            input=json.dumps({"tags": page.tags, "scripts": scripts}),
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
