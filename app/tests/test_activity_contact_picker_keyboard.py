import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HTML = ROOT / "app/frontend/admin/index.html"


class ContactPickerKeyboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        content = HTML.read_text(encoding="utf-8")
        start = content.index("function openContactsModal()")
        end = content.index("function closeContactsModal()", start)
        cls.contacts_open = content[start:end]
        cls.html = content

    def test_mobile_closes_existing_keyboard_before_display(self):
        self.assertIn(
            "if (isAndroidUserAgent()) dismissAndroidPaymentKeyboard();",
            self.contacts_open,
        )
        self.assertLess(
            self.contacts_open.index("dismissAndroidPaymentKeyboard();"),
            self.contacts_open.index('contactsModal.style.display = "flex"'),
        )

    def test_mobile_dialog_focuses_close_button_not_search(self):
        self.assertIn("if (isAndroidUserAgent()) {", self.contacts_open)
        self.assertIn(
            "closeContactsBtn?.focus({ preventScroll: true });", self.contacts_open
        )
        self.assertIn("return;", self.contacts_open)
        self.assertLess(
            self.contacts_open.index("return;", self.contacts_open.index("requestAnimationFrame")),
            self.contacts_open.index("contactSearchInput?.focus();"),
        )

    def test_desktop_search_autofocus_is_retained(self):
        self.assertIn("contactSearchInput?.focus();", self.contacts_open)
        self.assertIn('contactSearchInput.value = "";', self.contacts_open)
        self.assertIn("renderContacts(loadedContacts);", self.contacts_open)

    def test_contact_selection_still_uses_keyboard_safe_insert(self):
        self.assertIn(
            "focusPaymentFieldAfterAutomaticInsert(payOfferInput);", self.html
        )
        self.assertIn('contactSearchInput?.addEventListener(', self.html)


if __name__ == "__main__":
    unittest.main()
