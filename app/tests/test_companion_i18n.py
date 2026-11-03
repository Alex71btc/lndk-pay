import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CompanionLocalizationTests(unittest.TestCase):
    def test_five_complete_native_locales_and_english_default(self):
        resource_root = ROOT / "android-companion" / "app" / "src" / "main" / "res"

        def read(folder):
            elements = ET.parse(resource_root / folder / "strings.xml").getroot()
            keys = [element.attrib["name"] for element in elements]
            self.assertEqual(len(keys), len(set(keys)), f"Duplicate key in {folder}")
            values = {element.attrib["name"]: element.text for element in elements}
            self.assertTrue(all(values.values()), f"Empty translation in {folder}")
            return values

        english = read("values")
        self.assertEqual(english, read("values-en"))
        self.assertEqual(english["save_server"], "Save server")
        for lang in ("de", "es", "fr", "pl"):
            with self.subTest(lang=lang):
                translated = read(f"values-{lang}")
                self.assertEqual(set(english), set(translated))
                self.assertNotEqual(english["safety_note"], translated["safety_note"])


if __name__ == "__main__":
    unittest.main()
