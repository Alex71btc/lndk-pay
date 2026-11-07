import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException

import backend.app as app_module
from backend import companion_push


def b64url(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def encrypt_action(vapid_private_key, payload):
    padded_key = vapid_private_key + "=" * ((4 - len(vapid_private_key) % 4) % 4)
    private_bytes = base64.urlsafe_b64decode(padded_key)
    server_private = ec.derive_private_key(
        int.from_bytes(private_bytes, "big"), ec.SECP256R1()
    )
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral.exchange(ec.ECDH(), server_private.public_key())
    salt = os.urandom(16)
    nonce = os.urandom(12)
    action_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=companion_push.BROWSER_ENVELOPE_INFO,
    ).derive(shared_secret)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = AESGCM(action_key).encrypt(
        nonce,
        plaintext,
        companion_push.BROWSER_ENVELOPE_INFO,
    )
    public_numbers = ephemeral.public_key().public_numbers()
    ephemeral_point = (
        b"\x04"
        + public_numbers.x.to_bytes(32, "big")
        + public_numbers.y.to_bytes(32, "big")
    )
    return b64url(b"\x01" + ephemeral_point + salt + nonce + ciphertext)


class BrowserActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        self.db = Path(temp.name) / "pairing.db"
        companion_push.init_db(self.db)
        self.vapid_private_key = companion_push.generate_vapid_private_key()
        token, _ = companion_push.create_pairing_token(self.db)
        self.subscription = {
            "endpoint": "https://push.example.com/webpush/test",
            "p256dh": b64url(b"\x04" + b"\x11" * 64),
            "auth": b64url(b"\x22" * 16),
        }
        self.pair_action = {
            "operation": "pair",
            "issued_at": int(time.time()),
            "action_nonce": b64url(os.urandom(32)),
            "pairing_token": token,
            "device_name": "Umbrel Android Test",
            **self.subscription,
        }
        self.payload = self.request_for(self.pair_action)
        self.request = SimpleNamespace(
            cookies={"csrf_token": "test-csrf"},
            headers={"x-csrf-token": "test-csrf"},
        )

    def request_for(self, action):
        return app_module.CompanionBrowserActionRequest(
            envelope=encrypt_action(self.vapid_private_key, action)
        )

    def patches(self):
        return (
            patch.object(app_module, "DB_PATH", self.db),
            patch.object(app_module, "require_pay_auth"),
            patch.object(
                app_module,
                "_companion_vapid_private_key",
                return_value=self.vapid_private_key,
            ),
            patch.object(
                app_module,
                "_companion_vapid_subject",
                return_value="mailto:test@example.com",
            ),
        )

    async def test_requires_login_before_decrypting(self):
        with (
            patch.object(app_module, "DB_PATH", self.db),
            patch.object(
                app_module,
                "require_pay_auth",
                side_effect=HTTPException(status_code=401),
            ),
        ):
            with self.assertRaises(HTTPException) as result:
                await app_module.api_admin_companion_browser_action(
                    self.payload, self.request
                )

        self.assertEqual(result.exception.status_code, 401)
        self.assertEqual(companion_push.list_devices(self.db), [])

    async def test_requires_csrf_before_decrypting(self):
        request = SimpleNamespace(
            cookies={"csrf_token": "test-csrf"},
            headers={},
        )
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(HTTPException) as result:
                await app_module.api_admin_companion_browser_action(
                    self.payload, request
                )

        self.assertEqual(result.exception.status_code, 403)
        self.assertEqual(companion_push.list_devices(self.db), [])

    async def test_pair_uses_encrypted_confirmation_without_browser_token(self):
        sender = AsyncMock()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            patch.object(companion_push, "send_pairing_confirmation", sender),
        ):
            response = await app_module.api_admin_companion_browser_action(
                self.payload, self.request
            )

        data = json.loads(response.body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["operation"], "pair")
        response_text = json.dumps(data)
        self.assertNotIn("device_token", response_text)
        self.assertNotIn(self.pair_action["pairing_token"], response_text)
        self.assertEqual(len(companion_push.list_devices(self.db)), 1)
        sender.assert_awaited_once()

    async def test_failed_pair_confirmation_restores_existing_device(self):
        old_token, _ = companion_push.create_pairing_token(self.db)
        old_device = companion_push.register_device(
            self.db,
            pairing_token=old_token,
            name="Existing device",
            **self.subscription,
        )
        sender = AsyncMock(side_effect=RuntimeError("Simulated push failure"))
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            patch.object(companion_push, "send_pairing_confirmation", sender),
        ):
            with self.assertRaises(HTTPException) as result:
                await app_module.api_admin_companion_browser_action(
                    self.payload, self.request
                )

        self.assertEqual(result.exception.status_code, 503)
        devices = companion_push.list_devices(self.db)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["id"], old_device["id"])
        updated = companion_push.update_device_subscription(
            self.db,
            device_token=old_device["device_token"],
            **self.subscription,
        )
        self.assertEqual(updated["id"], old_device["id"])

    async def test_renewal_rolls_back_when_confirmation_fails(self):
        token, _ = companion_push.create_pairing_token(self.db)
        old_device = companion_push.register_device(
            self.db,
            pairing_token=token,
            name="Renewal device",
            **{
                **self.subscription,
                "endpoint": "https://push.example.com/webpush/old",
            },
        )
        action = {
            "operation": "renew",
            "issued_at": int(time.time()),
            "action_nonce": b64url(os.urandom(32)),
            "device_token": old_device["device_token"],
            **self.subscription,
        }
        sender = AsyncMock(side_effect=RuntimeError("No delivery"))
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            patch.object(
                companion_push, "send_browser_action_confirmation", sender
            ),
        ):
            with self.assertRaises(HTTPException) as result:
                await app_module.api_admin_companion_browser_action(
                    self.request_for(action), self.request
                )

        self.assertEqual(result.exception.status_code, 503)
        stored = companion_push.device_subscription(
            self.db, old_device["device_token"]
        )
        self.assertEqual(
            stored["endpoint"], "https://push.example.com/webpush/old"
        )

    async def test_revoke_is_authenticated_and_replay_safe(self):
        token, _ = companion_push.create_pairing_token(self.db)
        device = companion_push.register_device(
            self.db,
            pairing_token=token,
            name="Revoked device",
            **self.subscription,
        )
        action = {
            "operation": "revoke",
            "issued_at": int(time.time()),
            "action_nonce": b64url(os.urandom(32)),
            "device_token": device["device_token"],
        }
        request_payload = self.request_for(action)
        sender = AsyncMock()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            patch.object(
                companion_push, "send_browser_action_confirmation", sender
            ),
        ):
            response = await app_module.api_admin_companion_browser_action(
                request_payload, self.request
            )
            with self.assertRaises(HTTPException) as replay:
                await app_module.api_admin_companion_browser_action(
                    request_payload, self.request
                )

        self.assertEqual(json.loads(response.body)["operation"], "revoke")
        self.assertEqual(replay.exception.status_code, 409)
        self.assertEqual(companion_push.list_devices(self.db), [])


if __name__ == "__main__":
    unittest.main()
