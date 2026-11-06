import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUSH_SERVICE = (
    ROOT
    / "android-companion"
    / "app"
    / "src"
    / "main"
    / "java"
    / "com"
    / "bolt12pay"
    / "companion"
    / "PushServiceImpl.java"
)
APP_BACKEND = ROOT / "app" / "backend" / "app.py"


class CompanionNotificationPrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.push_service = PUSH_SERVICE.read_text(encoding="utf-8")
        cls.backend = APP_BACKEND.read_text(encoding="utf-8")

    def test_only_decrypted_messages_can_be_rendered(self):
        self.assertIn("if (!message.getDecrypted())", self.push_service)

    def test_comment_display_requires_the_local_opt_in(self):
        self.assertIn("settings.showPaymentComments()", self.push_service)
        self.assertIn('? PaymentComment.sanitize(payload.optString("comment", ""))', self.push_service)

    def test_lockscreen_version_stays_generic_and_private(self):
        public_start = self.push_service.index("Notification publicVersion")
        private_start = self.push_service.index("Notification.Builder notificationBuilder")
        public_version = self.push_service[public_start:private_start]

        self.assertIn("push_private_title", public_version)
        self.assertIn("push_private_body", public_version)
        self.assertNotIn("comment", public_version)
        self.assertIn("setVisibility(Notification.VISIBILITY_PUBLIC)", public_version)
        self.assertIn("setVisibility(Notification.VISIBILITY_PRIVATE)", self.push_service)
        self.assertIn("setPublicVersion(publicVersion)", self.push_service)

    def test_public_channel_setting_suppresses_sensitive_text(self):
        self.assertIn("manager.getNotificationChannel(CHANNEL_ID)", self.push_service)
        self.assertIn("channel.getLockscreenVisibility()", self.push_service)
        self.assertIn("== Notification.VISIBILITY_PUBLIC", self.push_service)
        self.assertIn('? ""\n                        : comment;', self.push_service)

    def test_lnurl_comment_text_is_not_written_to_server_logs(self):
        self.assertNotIn("comment={comment!r}", self.backend)


if __name__ == "__main__":
    unittest.main()
