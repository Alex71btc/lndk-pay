import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOGIN_HTML = PROJECT_ROOT / "app" / "frontend" / "admin" / "pay-login.html"


class PayLoginInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = LOGIN_HTML.read_text(encoding="utf-8")

    def test_enter_and_button_share_the_native_form_submit_path(self):
        self.assertIn(
            '<form id="loginForm" action="/api/auth/login" method="post" novalidate>',
            self.html,
        )
        self.assertIn('<button id="loginBtn" type="submit">', self.html)
        self.assertIn('loginForm.addEventListener("submit", (event) => {', self.html)
        self.assertIn("event.preventDefault();", self.html)
        self.assertIn("void doLogin();", self.html)
        self.assertNotIn('passwordEl.addEventListener("keydown"', self.html)

    def test_login_submission_is_validated_and_single_flight(self):
        self.assertIn("let loginInProgress = false;", self.html)
        self.assertIn("if (loginInProgress || loginBtn.disabled) return;", self.html)
        self.assertIn("if (!password) {", self.html)
        self.assertIn("loginInProgress = true;", self.html)
        self.assertIn("loginInProgress = false;", self.html)
        self.assertIn("loginBtn.disabled = true;", self.html)

    def test_password_stays_in_the_same_origin_post_body(self):
        self.assertIn('type="password"', self.html)
        self.assertIn('autocomplete="current-password"', self.html)
        self.assertIn('const password = passwordEl.value || "";', self.html)
        self.assertIn('fetch("/api/auth/login", {', self.html)
        self.assertIn('method: "POST"', self.html)
        self.assertIn('credentials: "same-origin"', self.html)
        self.assertIn("body: JSON.stringify({ password })", self.html)
        self.assertNotIn("passwordEl.value.trim()", self.html)

    def test_post_login_redirect_is_limited_to_same_origin_paths(self):
        self.assertIn("function getSafeNextPath()", self.html)
        self.assertIn('requested.startsWith("//")', self.html)
        self.assertIn("target.origin !== window.location.origin", self.html)
        self.assertIn("window.location.assign(getSafeNextPath());", self.html)


if __name__ == "__main__":
    unittest.main()
