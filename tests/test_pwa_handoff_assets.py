import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "app" / "frontend" / "admin"
PUBLIC = ROOT / "app" / "frontend" / "public"
ANDROID = ROOT / "android-companion" / "app" / "src" / "main"


class PwaInstallAssetsTest(unittest.TestCase):
    def test_manifests_have_stable_distinct_ids_and_self_relationships(self):
        pay = json.loads((ADMIN / "pay.webmanifest").read_text())
        console = json.loads((PUBLIC / "public.webmanifest").read_text())

        self.assertEqual("/pay", pay["id"])
        self.assertEqual("/app", console["id"])
        self.assertNotEqual(pay["id"], console["id"])
        self.assertEqual("/pay.webmanifest", pay["related_applications"][0]["url"])
        self.assertEqual(
            "/public.webmanifest", console["related_applications"][0]["url"]
        )

    def test_both_install_buttons_use_the_shared_state_controller(self):
        pay_html = (ADMIN / "index.html").read_text()
        console_html = (PUBLIC / "index.html").read_text()
        controller = (ADMIN / "pwa-install.js").read_text()

        self.assertIn('id="installBtn" type="button" hidden', pay_html)
        self.assertIn('src="/pwa-install.js"', pay_html)
        self.assertIn('src="/pwa-install.js"', console_html)
        self.assertIn('navigator.serviceWorker.register(', controller)
        self.assertIn('window.addEventListener("beforeinstallprompt"', controller)
        self.assertIn('window.addEventListener("appinstalled"', controller)
        self.assertIn("navigator.getInstalledRelatedApps", controller)
        self.assertIn('(display-mode: standalone)', controller)


class PaymentIntentHandoffTest(unittest.TestCase):
    def test_handoff_uses_fragment_and_session_storage_only(self):
        bridge = (ADMIN / "pay-intent.html").read_text()
        pay_html = (ADMIN / "index.html").read_text()

        self.assertIn("window.location.hash", bridge)
        self.assertIn("sessionStorage.setItem(STORAGE_KEY, target)", bridge)
        self.assertIn('window.location.replace("/pay")', bridge)
        self.assertNotIn("/api/pay-", bridge)
        self.assertNotIn("fetch(", bridge)

        self.assertIn("consumeIncomingLightningIntent();", pay_html)
        self.assertIn('window.__t("intent.review")', pay_html)


class AndroidCompanionAssetsTest(unittest.TestCase):
    def test_manifest_handles_lightning_and_amethyst_bip321_with_brand_icon(self):
        manifest = (ANDROID / "AndroidManifest.xml").read_text()

        self.assertIn('android:scheme="lightning"', manifest)
        self.assertIn('android:scheme="bitcoin"', manifest)
        self.assertIn('android:icon="@drawable/bolt12_pay_logo"', manifest)
        self.assertTrue(
            (ANDROID / "res" / "drawable-nodpi" / "bolt12_pay_logo.png").exists()
        )


if __name__ == "__main__":
    unittest.main()
