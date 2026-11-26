"""Every /api/* route rejects callers without a Pay session unless it is allowlisted."""

import re
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend import app as backend, config


PASSWORD = "test-owner-password"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
# Regression guard for the handlers that once shipped without any session check.
FORMERLY_UNPROTECTED = {
    ("GET", "/api/identity-config"),
    ("POST", "/api/identity-config"),
    ("DELETE", "/api/alias/{name}"),
    ("PATCH", "/api/alias/{name}"),
    ("GET", "/api/debug/payments"),
    ("GET", "/api/contacts"),
    ("GET", "/api/debug/pending-zaps"),
    ("POST", "/api/decode-offer"),
}


def api_routes():
    for route in backend.app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/"):
            for method in sorted(route.methods - {"HEAD"}):
                yield method, route.path


def concrete(path):
    return re.sub(r"\{[^}]+\}", "x", path)


class ApiAccessPolicyTests(unittest.TestCase):
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
        ))
        # A rejected request must never reach a wallet backend.
        stack.enter_context(patch.object(
            backend, "_read_macaroon_hex", side_effect=AssertionError("LND accessed"),
        ))

    def client(self):
        client = TestClient(backend.app, base_url="https://testserver", raise_server_exceptions=False)
        self.addCleanup(client.close)
        return client

    def logged_in(self):
        client = self.client()
        self.assertEqual(client.post("/api/auth/login", json={"password": PASSWORD}).status_code, 200)
        return client

    def private_routes(self):
        return [r for r in api_routes() if r not in backend.PUBLIC_API_ROUTES]

    def test_allowlists_name_real_routes(self):
        routes = set(api_routes())
        self.assertLessEqual(backend.PUBLIC_API_ROUTES, routes)
        self.assertLessEqual(backend.FIRST_RUN_API_ROUTES, routes)
        self.assertFalse(backend.PUBLIC_API_ROUTES & backend.FIRST_RUN_API_ROUTES)
        self.assertLessEqual(FORMERLY_UNPROTECTED, routes)
        self.assertFalse(FORMERLY_UNPROTECTED & backend.PUBLIC_API_ROUTES)

    def test_every_private_route_rejects_anonymous_callers(self):
        config.initialize_ui_password(PASSWORD)
        client = self.client()
        private = self.private_routes()
        self.assertGreater(len(private), 60)
        for method, path in private:
            with self.subTest(method=method, path=path):
                response = client.request(method, concrete(path), json={})
                self.assertEqual(response.status_code, 401, response.text)

    def test_before_setup_only_first_run_routes_skip_the_session(self):
        client = self.client()
        for method, path in self.private_routes():
            if (method, path) in backend.FIRST_RUN_API_ROUTES:
                continue
            with self.subTest(method=method, path=path):
                response = client.request(method, concrete(path), json={})
                self.assertEqual(response.status_code, 403, response.text)

    def test_writes_need_csrf_token_even_with_a_session(self):
        config.initialize_ui_password(PASSWORD)
        client = self.logged_in()
        for method, path in self.private_routes():
            if method not in UNSAFE:
                continue
            with self.subTest(method=method, path=path):
                response = client.request(method, concrete(path), json={})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertIn("CSRF", response.text)

    def test_writes_from_another_origin_on_the_same_site_are_rejected(self):
        config.initialize_ui_password(PASSWORD)
        client = self.logged_in()
        headers = {"X-CSRF-Token": client.cookies["csrf_token"], "Sec-Fetch-Site": "same-site"}
        response = client.post("/api/alias", json={"name": "x", "description": "x"}, headers=headers)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("Cross-origin", response.text)

    def test_identity_payload_is_bounded(self):
        config.initialize_ui_password(PASSWORD)
        client = self.logged_in()
        headers = {"X-CSRF-Token": client.cookies["csrf_token"]}
        pubkey = "a" * 64
        for payload in (
            {"alias": "x" * 65, "nostr_pubkey": pubkey},
            {"alias": "alice", "nostr_pubkey": pubkey, "relays": ["wss://r.example"] * 21},
            {"alias": "alice", "nostr_pubkey": pubkey, "relays": ["wss://" + "r" * 300]},
        ):
            with self.subTest(payload=str(payload)[:60]):
                response = client.post("/api/identity-config", json=payload, headers=headers)
                self.assertIn(response.status_code, {400, 422}, response.text)
        response = client.post(
            "/api/identity-config",
            json={"alias": "alice", "nostr_pubkey": pubkey, "relays": ["wss://r.example"]},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_wildcard_cors_never_allows_credentials(self):
        response = self.client().get(
            "/api/health", headers={"Origin": "https://evil.example", "Cookie": "pay_session=x"},
        )
        self.assertNotEqual(response.headers.get("access-control-allow-credentials"), "true")
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "https://evil.example")


if __name__ == "__main__":
    unittest.main()
