from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import app as backend, config


OLD_PASSWORD = "test-owner-password"
NEW_PASSWORD = "test-replacement-password"
NWC_CONNECTIONS = "/api/admin/nwc/connections"
SETUP_ADDRESS = {"public_bolt12_address": "bolt12@pay.local"}


class UiPasswordSessionTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        data_dir = Path(stack.enter_context(TemporaryDirectory()))
        stack.enter_context(patch.object(config, "CONFIG_PATH", str(data_dir / "config.json")))
        stack.enter_context(patch.multiple(
            backend,
            PAY_UI_PASSWORD="",
            PAY_SESSIONS={},
            NWC_SESSIONS={},
            _LOGIN_FAILURES={},
            _LOGIN_LOCKOUTS={},
            LOGIN_FAILURE_DELAY_MS=0,
            list_nwc_connections=lambda: [],
        ))

    def new_client(self):
        client = TestClient(backend.app, base_url="https://testserver")
        self.addCleanup(client.close)
        return client

    def login(self, client, password):
        return client.post("/api/auth/login", json={"password": password})

    def unlock_nwc(self, client, password):
        return client.post("/api/admin/nwc/unlock", json={"password": password}, headers=self.csrf(client))

    @staticmethod
    def csrf(client):
        return {"X-CSRF-Token": client.cookies.get("csrf_token", "")}

    def assert_password_change_revokes_sessions(self, change_password):
        config.initialize_ui_password(OLD_PASSWORD)
        first = self.new_client()
        second = self.new_client()
        for client in (first, second):
            self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 200)
            self.assertEqual(self.unlock_nwc(client, OLD_PASSWORD).status_code, 200)
            self.assertEqual(client.get(NWC_CONNECTIONS).status_code, 200)

        change_password(first)

        for client in (first, second):
            self.assertIs(client.get("/api/auth/session").json()["ok"], False)
            self.assertEqual(client.get("/api/setup/config").status_code, 401)
            redirect = client.get("/pay", follow_redirects=False)
            self.assertEqual(redirect.status_code, 307)
            self.assertTrue(redirect.headers["location"].startswith("/pay-login?"))
            self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 401)
            self.assertEqual(self.login(client, NEW_PASSWORD).status_code, 200)
            # A fresh Pay cookie must not restore the old NWC unlock.
            response = client.get(NWC_CONNECTIONS)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"], "NWC unlock required")
            self.assertEqual(self.unlock_nwc(client, NEW_PASSWORD).status_code, 200)
            self.assertEqual(client.get(NWC_CONNECTIONS).status_code, 200)

    def test_setup_password_change_revokes_pay_and_nwc_sessions(self):
        def change_password(client):
            response = client.post(
                "/api/setup/config",
                json={**SETUP_ADDRESS, "password": NEW_PASSWORD, "current_password": OLD_PASSWORD},
                headers=self.csrf(client),
            )
            self.assertEqual(response.status_code, 200, response.text)

        self.assert_password_change_revokes_sessions(change_password)

    def test_setup_password_change_requires_current_password_and_csrf(self):
        config.initialize_ui_password(OLD_PASSWORD)
        client = self.new_client()
        self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 200)
        change = {**SETUP_ADDRESS, "password": NEW_PASSWORD}

        self.assertEqual(client.post("/api/setup/config", json=change).status_code, 403)
        for current in ({}, {"current_password": ""}, {"current_password": "wrong"}):
            response = client.post("/api/setup/config", json={**change, **current}, headers=self.csrf(client))
            self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.login(self.new_client(), OLD_PASSWORD).status_code, 200)
        self.assertEqual(self.login(self.new_client(), NEW_PASSWORD).status_code, 401)
        self.assertNotIn("ui_password_hash", client.get("/api/setup/config").json())

    def test_external_password_change_revokes_pay_and_nwc_sessions(self):
        def change_password(_client):
            # StartOS writes the new hash to the running service's config file.
            settings = config.load_config()
            settings["ui_password_hash"] = config.hash_ui_password(NEW_PASSWORD)
            config.save_config(settings)

        self.assert_password_change_revokes_sessions(change_password)

    def test_setup_save_without_password_change_keeps_sessions(self):
        config.initialize_ui_password(OLD_PASSWORD)
        client = self.new_client()
        self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 200)
        self.assertEqual(self.unlock_nwc(client, OLD_PASSWORD).status_code, 200)

        for payload in (
            SETUP_ADDRESS,
            {**SETUP_ADDRESS, "password": OLD_PASSWORD, "current_password": OLD_PASSWORD},
        ):
            response = client.post("/api/setup/config", json=payload, headers=self.csrf(client))
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIs(client.get("/api/auth/session").json()["ok"], True)
            self.assertEqual(client.get(NWC_CONNECTIONS).status_code, 200)

    def test_environment_password_session_expires_when_stored_password_takes_over(self):
        with patch.object(backend, "PAY_UI_PASSWORD", OLD_PASSWORD):
            client = self.new_client()
            self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 200)
            self.assertIs(client.get("/api/auth/session").json()["ok"], True)

            config.initialize_ui_password(NEW_PASSWORD)

            self.assertIs(client.get("/api/auth/session").json()["ok"], False)
            self.assertEqual(self.login(client, OLD_PASSWORD).status_code, 401)
            self.assertEqual(self.login(client, NEW_PASSWORD).status_code, 200)
            self.assertIs(client.get("/api/auth/session").json()["ok"], True)
