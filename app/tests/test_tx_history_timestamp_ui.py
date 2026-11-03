import json
import re
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TxHistoryTimestampUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (
            PROJECT_ROOT / "app" / "frontend" / "admin" / "index.html"
        ).read_text(encoding="utf-8")

    def test_formats_activity_timestamp_in_selected_language(self):
        script = """
const assert = require("node:assert/strict");
let language;
const window = { getLang: () => language };
"""
        for name in ("parseTxTimestamp", "formatTxTimestamp"):
            script += re.search(
                rf"^      function {name}\(.*?^      \}}", self.html, re.S | re.M
            ).group(0) + "\n"
        script += """
const item = {created_at: "2026-11-03T10:15:00Z"};
for (language of ["en", "de", "es", "fr", "pl"]) {
  const date = new Date(item.created_at);
  const expected = new Intl.DateTimeFormat(language, {dateStyle: "medium", timeStyle: "short"}).format(date);
  assert.deepEqual(formatTxTimestamp(item), {text: expected, iso: date.toISOString()});
}
"""
        result = subprocess.run(["node", "-"], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('class="txTimestamp"', self.html)

    def test_supports_legacy_timestamp_shapes_and_missing_values(self):
        self.assertIn("function parseTxTimestamp(value)", self.html)
        self.assertIn("numericValue * 1000", self.html)
        self.assertIn("numericValue / 1e3", self.html)
        self.assertIn("numericValue / 1e6", self.html)
        self.assertIn("parseTxTimestamp(item.created_at)", self.html)
        self.assertIn("parseTxTimestamp(item.settled_at)", self.html)
        self.assertIn(
            'window.__t("history.timestamp_unavailable")',
            self.html,
        )

    def test_has_localized_missing_timestamp_labels(self):
        labels = set()
        for language in ("en", "de", "es", "fr", "pl"):
            path = PROJECT_ROOT / "app" / "i18n" / "pay" / f"{language}.json"
            text = json.loads(path.read_text(encoding="utf-8"))["history.timestamp_unavailable"]
            self.assertTrue(text.strip())
            labels.add(text)
        self.assertEqual(len(labels), 5)
        self.assertIn("Date and time unavailable", labels)
        self.assertIn("Datum und Uhrzeit nicht verfügbar", labels)

    def test_timestamp_layout_is_responsive(self):
        self.assertIn(".txTimestamp {", self.html)
        self.assertIn("overflow-wrap: anywhere", self.html)
        self.assertIn("font-variant-numeric: tabular-nums", self.html)

    def test_auto_refresh_reads_local_history_without_forcing_lnd_sync(self):
        refresh_start = self.html.index("function startTxHistoryAutoRefresh()")
        refresh_end = self.html.index(
            "function stopTxHistoryAutoRefresh()",
            refresh_start,
        )
        refresh_body = self.html[refresh_start:refresh_end]

        self.assertIn("await window.renderTxHistory()", refresh_body)
        self.assertNotIn("syncTxHistory()", refresh_body)
        self.assertIn("}, 5000);", refresh_body)


if __name__ == "__main__":
    unittest.main()
