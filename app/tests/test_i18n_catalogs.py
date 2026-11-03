"""Reject incomplete catalogs before a browser can silently fall back to English."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_i18n


class CatalogValidationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.scope = Path(temp.name)
        for lang in build_i18n.LANGUAGES:
            self.write(lang, {"status.wait": "Wait {seconds}s"})

    def write(self, lang, values):
        (self.scope / f"{lang}.json").write_text(json.dumps(values), encoding="utf-8")

    def test_duplicates_fail_before_json_overwrites_a_value(self):
        (self.scope / "es.json").write_text('{"status.wait":"A","status.wait":"B"}')
        with self.assertRaisesRegex(ValueError, "Duplicate translation key"):
            build_i18n.load_scope(self.scope)

    def test_missing_keys_and_extra_keys_fail(self):
        for catalog in ({}, {"status.wait": "Wait {seconds}s", "extra": "Value"}):
            with self.subTest(catalog=catalog):
                self.write("pl", catalog)
                with self.assertRaisesRegex(ValueError, "missing=.*extra="):
                    build_i18n.load_scope(self.scope)

    def test_interpolation_requires_matching_names_in_every_locale(self):
        self.write("fr", {"status.wait": "Patienter {secondes}s"})
        with self.assertRaisesRegex(ValueError, "placeholder mismatch"):
            build_i18n.load_scope(self.scope)

    def test_empty_text_and_html_are_rejected(self):
        for value in (" ", "<b>{seconds}</b>"):
            with self.subTest(value=value):
                self.write("de", {"status.wait": value})
                with self.assertRaises(ValueError):
                    build_i18n.load_scope(self.scope)

    def test_products_match_the_reviewed_sources(self):
        check = subprocess.run(
            [sys.executable, str(ROOT / "scripts/build_i18n.py"), "--check"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
