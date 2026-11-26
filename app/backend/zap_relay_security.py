"""Restrict sender-selected Zap receipt relays to public endpoints."""

import asyncio
import ipaddress
import socket

from websockets.exceptions import SecurityError
from websockets.legacy.client import Connect
from websockets.uri import parse_uri


class _NoRedirectConnect(Connect):
    """Never follow redirects from untrusted receipt relays."""

    def handle_redirect(self, uri):
        raise SecurityError("Zap relay redirects are not allowed")


def _is_public_address(value):
    try:
        if "%" in value:
            return False

        address = ipaddress.ip_address(value)

        if address.version == 6 and (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            return False

        return (
            address.is_global
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_unspecified
        )
    except ValueError:
        return False


async def _resolve_relay_addresses(host, port):
    records = await asyncio.get_running_loop().getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return list(dict.fromkeys(record[4][0] for record in records))


async def connect_public_zap_relay(
    relay_url, *, open_timeout, close_timeout
):
    uri = parse_uri(relay_url)

    if uri.user_info is not None or "%" in uri.host:
        raise SecurityError("Invalid Zap relay address")

    addresses = await asyncio.wait_for(
        _resolve_relay_addresses(uri.host, uri.port),
        timeout=open_timeout,
    )

    if not addresses or not all(
        _is_public_address(address) for address in addresses
    ):
        raise SecurityError("Zap relay must resolve to public addresses")

    # Prefer IPv4 where available, including on IPv4-only hosts.
    address = next(
        (value for value in addresses if ":" not in value),
        addresses[0],
    )

    # Pin the validated IP while preserving the original HTTP Host
    # and, for WSS, TLS hostname and certificate verification.
    options = {
        "host": address,
        "port": uri.port,
        "open_timeout": open_timeout,
        "close_timeout": close_timeout,
    }

    if uri.secure:
        options["server_hostname"] = uri.host

    return _NoRedirectConnect(relay_url, **options)
