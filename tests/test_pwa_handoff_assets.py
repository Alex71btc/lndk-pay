import json
import re
import struct
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "app" / "frontend" / "admin"
PUBLIC = ROOT / "app" / "frontend" / "public"
ANDROID = ROOT / "android-companion" / "app" / "src" / "main"
BACKEND = ROOT / "app" / "backend" / "app.py"


def png_size(path):
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError(f"Not a PNG file: {path}")
    return struct.unpack(">II", data[16:24])


class PwaInstallAssetsTest(unittest.TestCase):
    def test_pay_and_console_use_one_stable_pwa_identity(self):
        pay = json.loads((ADMIN / "pay.webmanifest").read_text())
        console = json.loads((PUBLIC / "public.webmanifest").read_text())
        pay_html = (ADMIN / "index.html").read_text()
        console_html = (PUBLIC / "index.html").read_text()

        self.assertEqual("/pay", pay["id"])
        self.assertEqual(pay["id"], console["id"])
        self.assertEqual(pay["start_url"], console["start_url"])
        self.assertEqual(pay["scope"], console["scope"])
        self.assertEqual("/pay.webmanifest", pay["related_applications"][0]["url"])
        self.assertEqual("/pay", pay["related_applications"][0]["id"])
        self.assertEqual(
            "/pay.webmanifest", console["related_applications"][0]["url"]
        )
        self.assertEqual("/pay", console["related_applications"][0]["id"])
        self.assertIn('<link rel="manifest" href="/pay.webmanifest"', pay_html)
        self.assertIn('<link rel="manifest" href="/pay.webmanifest"', console_html)
        self.assertNotIn('<link rel="manifest" href="/public.webmanifest"', console_html)

    def test_service_worker_has_effective_network_only_fetch_handler(self):
        service_worker = (PUBLIC / "service-worker.js").read_text()

        self.assertIn('self.addEventListener("fetch"', service_worker)
        self.assertIn("event.respondWith(fetch(event.request))", service_worker)
        self.assertIn('const LEGACY_CACHE_PREFIX = "bolt12-pay-"', service_worker)
        self.assertIn("caches.keys()", service_worker)
        self.assertIn("key.startsWith(LEGACY_CACHE_PREFIX)", service_worker)
        self.assertIn("caches.delete(key)", service_worker)

    def test_service_worker_update_deletes_only_legacy_app_caches(self):
        service_worker = (PUBLIC / "service-worker.js").read_text()
        script = """
const assert = require('node:assert/strict');
const vm = require('node:vm');
const listeners = {};
const deleted = [];
let skipped = false;
let claimed = false;
const context = {
  self: {
    addEventListener(name, handler) { listeners[name] = handler; },
    skipWaiting() { skipped = true; },
    clients: { claim: async () => { claimed = true; } },
  },
  caches: {
    keys: async () => ['bolt12-pay-v2', 'another-app-v1'],
    delete: async key => { deleted.push(key); return true; },
  },
  fetch: async request => `network:${request}`,
  Promise,
};
vm.runInNewContext(SOURCE, context);
(async () => {
  listeners.install({});
  assert.equal(skipped, true);
  let activation;
  listeners.activate({waitUntil(promise) { activation = promise; }});
  await activation;
  assert.deepEqual(deleted, ['bolt12-pay-v2']);
  assert.equal(claimed, true);
  let response;
  listeners.fetch({request: '/pay', respondWith(promise) { response = promise; }});
  assert.equal(await response, 'network:/pay');
})().catch(error => { console.error(error); process.exitCode = 1; });
""".replace("SOURCE", json.dumps(service_worker), 1)
        result = subprocess.run(
            ["node", "-"],
            input=script,
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_javascript_assets_are_versioned_with_the_app_release(self):
        version = (ROOT / "app" / "VERSION").read_text().strip()
        pay_html = (ADMIN / "index.html").read_text()
        login_html = (ADMIN / "pay-login.html").read_text()
        console_html = (PUBLIC / "index.html").read_text()
        backend = BACKEND.read_text()

        for source in (pay_html, login_html, console_html):
            for asset in re.findall(r'src="(/[^"]+\.js\?v=[^"]+)"', source):
                if asset.startswith(("/assets/i18n/", "/pwa-install.js")):
                    self.assertTrue(asset.endswith(f"?v={version}"), asset)

        self.assertIn(f'/assets/i18n/runtime.js?v={version}', pay_html)
        self.assertIn(f'/assets/i18n/pay.js?v={version}', pay_html)
        self.assertIn(f'/pwa-install.js?v={version}', pay_html)
        self.assertIn('runtime.js?v={escape(APP_VERSION)}', backend)
        self.assertIn('alias.js?v={escape(APP_VERSION)}', backend)
        self.assertIn('landing.js?v={escape(APP_VERSION)}', backend)
        self.assertNotRegex(
            "\n".join((pay_html, login_html, console_html, backend)),
            r'src="/(?:assets/i18n/[^"?]+|pwa-install)\.js"',
        )

    def test_manifests_reference_icons_with_truthful_installable_sizes(self):
        for manifest_path in (
            ADMIN / "pay.webmanifest",
            PUBLIC / "public.webmanifest",
        ):
            manifest = json.loads(manifest_path.read_text())
            icons = manifest["icons"]
            icon_192 = next(
                icon
                for icon in icons
                if icon["sizes"] == "192x192"
                and "any" in icon["purpose"].split()
            )
            icon_512 = next(
                icon
                for icon in icons
                if icon["sizes"] == "512x512"
                and "any" in icon["purpose"].split()
            )
            maskable_512 = next(
                icon
                for icon in icons
                if icon["sizes"] == "512x512"
                and "maskable" in icon["purpose"].split()
            )

            self.assertEqual("/assets/icon-192.png", icon_192["src"])
            self.assertEqual(
                (192, 192), png_size(ROOT / "app" / icon_192["src"].lstrip("/"))
            )
            self.assertEqual("/assets/icon-512.png", icon_512["src"])
            self.assertEqual(
                (512, 512), png_size(ROOT / "app" / icon_512["src"].lstrip("/"))
            )
            self.assertEqual("/assets/icon-maskable.png", maskable_512["src"])
            self.assertEqual(
                (512, 512),
                png_size(ROOT / "app" / maskable_512["src"].lstrip("/")),
            )

    def test_both_install_buttons_use_the_shared_state_controller(self):
        pay_html = (ADMIN / "index.html").read_text()
        console_html = (PUBLIC / "index.html").read_text()
        controller = (ADMIN / "pwa-install.js").read_text()
        version = (ROOT / "app" / "VERSION").read_text().strip()

        self.assertIn('id="installBtn" type="button" hidden', pay_html)
        self.assertIn(f'src="/pwa-install.js?v={version}"', pay_html)
        self.assertIn(f'src="/pwa-install.js?v={version}"', console_html)
        self.assertIn('navigator.serviceWorker.register(', controller)
        self.assertIn("await registration.update()", controller)
        self.assertIn('"controllerchange"', controller)
        self.assertIn("reloadWhenUpdatedWorkerTakesControl", controller)
        self.assertIn("if (!window.isSecureContext)", controller)
        self.assertIn('setButtonState("insecure")', controller)
        self.assertIn('window.addEventListener("beforeinstallprompt"', controller)
        self.assertIn('window.addEventListener("appinstalled"', controller)
        self.assertIn("navigator.getInstalledRelatedApps", controller)
        self.assertIn('(display-mode: standalone)', controller)

    def test_install_help_explains_firefox_linux_limit(self):
        for scope, key in (("pay", "nav.install_manual"), ("console", "console.install_manual")):
            with self.subTest(scope=scope):
                catalogs = ROOT / "app" / "i18n" / scope
                german = json.loads((catalogs / "de.json").read_text())
                self.assertIn("Firefox unter Linux", german[key])
                for lang in ("en", "es", "fr", "pl"):
                    help_text = json.loads((catalogs / f"{lang}.json").read_text())[key]
                    self.assertIn("Firefox", help_text)
                    self.assertIn("Linux", help_text)

    def test_android_companion_download_is_android_only(self):
        pay_html = (ADMIN / "index.html").read_text()
        controller = (ADMIN / "pwa-install.js").read_text()
        backend = BACKEND.read_text()
        apk = ADMIN / "downloads" / "bolt12-pay-companion.apk"

        self.assertIn('id="androidCompanionBtn"', pay_html)
        self.assertIn('data-android-apk="/bolt12-pay-companion.apk"', pay_html)
        self.assertIn("function isAndroid()", controller)
        self.assertIn("button.hidden = !isAndroid()", controller)
        self.assertIn("window.location.assign(ANDROID_APK_PATH)", controller)
        self.assertIn("function isIos()", controller)
        self.assertIn('@app.get("/bolt12-pay-companion.apk")', backend)
        self.assertIn("application/vnd.android.package-archive", backend)
        self.assertTrue(apk.exists())
        self.assertTrue(apk.read_bytes().startswith(b"PK"))


class PaymentIntentHandoffTest(unittest.TestCase):
    def test_handoff_uses_fragment_and_session_storage_only(self):
        bridge = (ADMIN / "pay-intent.html").read_text()
        pay_html = (ADMIN / "index.html").read_text()

        self.assertIn("window.location.hash", bridge)
        self.assertIn("function isLightningAddress(value)", bridge)
        self.assertIn("sessionStorage.setItem(STORAGE_KEY, target)", bridge)
        self.assertIn('window.location.replace("/pay")', bridge)
        self.assertNotIn("/api/pay-", bridge)
        self.assertNotIn("fetch(", bridge)

        self.assertIn("consumeIncomingLightningIntent();", pay_html)
        self.assertIn('kind !== "ambiguous_address"', pay_html)
        self.assertIn('window.__t("intent.review")', pay_html)


class AndroidCompanionAssetsTest(unittest.TestCase):
    def test_manifest_handles_lightning_and_amethyst_bip321_with_brand_icon(self):
        manifest = (ANDROID / "AndroidManifest.xml").read_text()

        self.assertIn('android:scheme="lightning"', manifest)
        self.assertIn('android:scheme="bitcoin"', manifest)
        self.assertIn('android:icon="@mipmap/ic_app_info"', manifest)
        self.assertIn('android:name=".PaymentLinkReceiver"', manifest)
        self.assertIn('android:icon="@mipmap/ic_payment_handler"', manifest)
        self.assertTrue(
            (ANDROID / "res" / "drawable-nodpi" / "bolt12_pay_logo.png").exists()
        )
        self.assertTrue(
            (ANDROID / "res" / "mipmap-nodpi" / "ic_payment_handler.png").exists()
        )
        self.assertTrue(
            (ANDROID / "res" / "mipmap-nodpi" / "ic_app_info.png").exists()
        )
        self.assertTrue(
            (ANDROID / "res" / "mipmap-anydpi-v26" / "ic_launcher.xml").exists()
        )
        foreground = (
            ANDROID / "res" / "drawable" / "ic_launcher_foreground.xml"
        ).read_text()
        self.assertIn('android:width="58dp"', foreground)
        self.assertIn('@drawable/bolt12_pay_logo', foreground)

    def test_server_origin_is_stored_redundantly_and_synchronously(self):
        settings = (
            ANDROID
            / "java"
            / "com"
            / "bolt12pay"
            / "companion"
            / "ServerSettings.java"
        ).read_text()

        self.assertIn("AtomicFile", settings)
        self.assertIn(".commit()", settings)
        self.assertIn("server-url-v1", settings)


if __name__ == "__main__":
    unittest.main()
