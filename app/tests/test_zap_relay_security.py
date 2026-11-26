import unittest
from unittest.mock import AsyncMock, patch

from websockets.exceptions import SecurityError

from backend import zap_relay_security as security
from backend import app as backend


class ZapRelaySecurityTests(unittest.IsolatedAsyncioTestCase):

    def test_nonpublic_addresses_are_rejected(self):
        addresses = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
        ]

        for address in addresses:
            with self.subTest(address=address):
                self.assertFalse(
                    security._is_public_address(address)
                )

    def test_public_addresses_are_allowed(self):
        self.assertTrue(
            security._is_public_address("8.8.8.8")
        )
        self.assertTrue(
            security._is_public_address("2606:4700:4700::1111")
        )

    async def test_mixed_dns_results_are_rejected(self):
        with (
            patch.object(
                security,
                "_resolve_relay_addresses",
                AsyncMock(return_value=["8.8.8.8", "127.0.0.1"]),
            ),
            patch.object(security, "_NoRedirectConnect") as connect,
        ):
            with self.assertRaises(SecurityError):
                await security.connect_public_zap_relay(
                    "wss://relay.example",
                    open_timeout=5,
                    close_timeout=1,
                )

            connect.assert_not_called()

    async def test_public_ip_is_pinned_and_tls_hostname_preserved(self):
        with (
            patch.object(
                security,
                "_resolve_relay_addresses",
                AsyncMock(return_value=["8.8.8.8"]),
            ),
            patch.object(security, "_NoRedirectConnect") as connect,
        ):
            await security.connect_public_zap_relay(
                "wss://relay.example/",
                open_timeout=5,
                close_timeout=1,
            )

            connect.assert_called_once_with(
                "wss://relay.example/",
                host="8.8.8.8",
                port=443,
                server_hostname="relay.example",
                open_timeout=5,
                close_timeout=1,
            )

    def test_redirects_are_rejected(self):
        connection = object.__new__(security._NoRedirectConnect)

        with self.assertRaises(SecurityError):
            connection.handle_redirect("wss://other.example")

    async def test_rejected_receipt_has_no_unguarded_fallback(self):
        with (
            patch.object(
                backend,
                "connect_public_zap_relay",
                AsyncMock(side_effect=SecurityError("Rejected")),
            ),
            patch.object(backend.websockets, "connect") as connect,
        ):
            result = await backend._publish_nostr_event_to_relay(
                "wss://relay.example",
                {"id": "test", "kind": 9735},
            )

            self.assertFalse(result["ok"])
            connect.assert_not_called()
