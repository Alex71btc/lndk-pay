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
        self.assertIn("function formatTxTimestamp(item)", self.html)
        self.assertIn(
            'document.documentElement.lang === "de" ? "de-DE" : "en-US"',
            self.html,
        )
        self.assertIn('dateStyle: "medium"', self.html)
        self.assertIn('timeStyle: "short"', self.html)
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

    def test_has_german_and_english_missing_timestamp_labels(self):
        self.assertIn("Datum und Uhrzeit nicht verfügbar", self.html)
        self.assertIn("Date and time unavailable", self.html)

    def test_timestamp_layout_is_responsive(self):
        self.assertIn(".txTimestamp {", self.html)
        self.assertIn("overflow-wrap: anywhere", self.html)
        self.assertIn("font-variant-numeric: tabular-nums", self.html)


if __name__ == "__main__":
    unittest.main()
