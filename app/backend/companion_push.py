from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
import socket
import sqlite3
import time
import unicodedata
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import aiohttp
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import WebPushException, webpush_async


PAIRING_TTL_SECONDS = 10 * 60
PUSH_TTL_SECONDS = 24 * 60 * 60
MAX_PUSH_ATTEMPTS = 12
VAPID_PRIVATE_KEY_FIELD = "companion_vapid_private_key"
MAX_PUSH_COMMENT_CHARS = 160


class UnsafePushEndpointError(ValueError):
    pass


class _PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, delegate: aiohttp.abc.AbstractResolver | None = None):
        self._delegate = delegate or aiohttp.resolver.DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ):
        records = await self._delegate.resolve(host, port, family)
        if not records:
            raise OSError("Push endpoint did not resolve")
        for record in records:
            try:
                address = ipaddress.ip_address(record["host"])
            except ValueError as exc:
                raise UnsafePushEndpointError(
                    "Push endpoint resolved to an invalid address"
                ) from exc
            if not address.is_global:
                raise UnsafePushEndpointError(
                    "Push endpoint resolved to a non-public address"
                )
        return records

    async def close(self) -> None:
        await self._delegate.close()


class _NoRedirectSession:
    def __init__(self, session: aiohttp.ClientSession):
        self._session = session

    async def post(self, *args, **kwargs):
        kwargs["allow_redirects"] = False
        return await self._session.post(*args, **kwargs)


async def secure_webpush_async(**kwargs):
    connector = aiohttp.TCPConnector(resolver=_PublicOnlyResolver())
    async with aiohttp.ClientSession(connector=connector) as session:
        return await webpush_async(
            **kwargs,
            aiohttp_session=_NoRedirectSession(session),
        )


def _connect(db_path: Path | str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(db_path: Path | str) -> None:
    with _connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS companion_pairing_tokens (
                token_hash TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS companion_devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                endpoint TEXT NOT NULL UNIQUE,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_seen_at INTEGER,
                last_success_at INTEGER,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS companion_push_events (
                id TEXT PRIMARY KEY,
                payment_hash TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS companion_push_deliveries (
                event_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                delivered_at INTEGER,
                last_error TEXT,
                PRIMARY KEY (event_id, device_id),
                FOREIGN KEY(event_id) REFERENCES companion_push_events(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(device_id) REFERENCES companion_devices(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_companion_deliveries_due
            ON companion_push_deliveries(status, next_attempt_at);
            """
        )


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _decode_base64url(value: str, label: str) -> bytes:
    if not value or len(value) > 200:
        raise ValueError(f"Invalid {label}")
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid {label}") from exc


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def generate_vapid_private_key() -> str:
    vapid = Vapid()
    vapid.generate_keys()
    private_value = vapid.private_key.private_numbers().private_value
    return _encode_base64url(private_value.to_bytes(32, "big"))


def vapid_public_key(private_key: str) -> str:
    vapid = Vapid.from_string(private_key)
    raw_public_key = vapid.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return _encode_base64url(raw_public_key)


def validate_subscription(
    endpoint: str,
    p256dh: str,
    auth: str,
) -> dict[str, str]:
    endpoint = str(endpoint or "").strip()
    if not endpoint or len(endpoint) > 1000:
        raise ValueError("Invalid push endpoint")
    parsed = urlparse(endpoint)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("Push endpoint must be a clean HTTPS URL")
    if parsed.hostname.lower() == "localhost":
        raise ValueError("Local push endpoints are not accepted")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError("Private-network push endpoints are not accepted")

    public_key = _decode_base64url(str(p256dh or "").strip(), "p256dh")
    auth_secret = _decode_base64url(str(auth or "").strip(), "auth")
    if len(public_key) != 65 or public_key[0] != 4:
        raise ValueError("Invalid p256dh")
    if len(auth_secret) != 16:
        raise ValueError("Invalid auth secret")

    return {
        "endpoint": endpoint,
        "p256dh": str(p256dh).strip(),
        "auth": str(auth).strip(),
    }


def create_pairing_token(
    db_path: Path | str,
    *,
    now: int | None = None,
) -> tuple[str, int]:
    timestamp = int(time.time()) if now is None else int(now)
    expires_at = timestamp + PAIRING_TTL_SECONDS
    token = secrets.token_urlsafe(32)
    with _connect(db_path) as connection:
        connection.execute(
            "DELETE FROM companion_pairing_tokens WHERE expires_at < ?",
            (timestamp,),
        )
        connection.execute(
            """
            INSERT INTO companion_pairing_tokens(token_hash, created_at, expires_at)
            VALUES (?, ?, ?)
            """,
            (_hash_token(token), timestamp, expires_at),
        )
    return token, expires_at


def register_device(
    db_path: Path | str,
    *,
    pairing_token: str,
    name: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    subscription = validate_subscription(endpoint, p256dh, auth)
    device_name = " ".join(str(name or "Android Companion").split())[:80]
    if not device_name:
        device_name = "Android Companion"
    pairing_hash = _hash_token(str(pairing_token or ""))
    device_token = secrets.token_urlsafe(32)
    device_token_hash = _hash_token(device_token)

    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        pairing = connection.execute(
            """
            SELECT token_hash FROM companion_pairing_tokens
            WHERE token_hash = ? AND expires_at >= ?
            """,
            (pairing_hash, timestamp),
        ).fetchone()
        if pairing is None:
            raise PermissionError("Pairing token is invalid or expired")
        connection.execute(
            "DELETE FROM companion_pairing_tokens WHERE token_hash = ?",
            (pairing_hash,),
        )

        existing = connection.execute(
            "SELECT id, created_at FROM companion_devices WHERE endpoint = ?",
            (subscription["endpoint"],),
        ).fetchone()
        device_id = str(existing["id"]) if existing else secrets.token_urlsafe(12)
        created_at = int(existing["created_at"]) if existing else timestamp
        connection.execute(
            """
            INSERT INTO companion_devices(
                id, name, token_hash, endpoint, p256dh, auth, enabled,
                created_at, updated_at, last_seen_at, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                token_hash = excluded.token_hash,
                endpoint = excluded.endpoint,
                p256dh = excluded.p256dh,
                auth = excluded.auth,
                enabled = 1,
                updated_at = excluded.updated_at,
                last_seen_at = excluded.last_seen_at,
                last_error = NULL
            """,
            (
                device_id,
                device_name,
                device_token_hash,
                subscription["endpoint"],
                subscription["p256dh"],
                subscription["auth"],
                created_at,
                timestamp,
                timestamp,
            ),
        )

    return {
        "id": device_id,
        "name": device_name,
        "device_token": device_token,
        "created_at": created_at,
    }


def _device_for_token(
    connection: sqlite3.Connection,
    device_token: str,
) -> sqlite3.Row | None:
    if not device_token:
        return None
    return connection.execute(
        "SELECT * FROM companion_devices WHERE token_hash = ?",
        (_hash_token(device_token),),
    ).fetchone()


def update_device_subscription(
    db_path: Path | str,
    *,
    device_token: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    now: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now is None else int(now)
    subscription = validate_subscription(endpoint, p256dh, auth)
    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        device = _device_for_token(connection, device_token)
        if device is None:
            raise PermissionError("Unknown companion device")
        try:
            connection.execute(
                """
                UPDATE companion_devices
                SET endpoint = ?, p256dh = ?, auth = ?, enabled = 1,
                    updated_at = ?, last_seen_at = ?, last_error = NULL
                WHERE id = ?
                """,
                (
                    subscription["endpoint"],
                    subscription["p256dh"],
                    subscription["auth"],
                    timestamp,
                    timestamp,
                    device["id"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Push endpoint is already paired") from exc
    return {"id": device["id"], "name": device["name"], "enabled": True}


def unregister_device_token(db_path: Path | str, device_token: str) -> bool:
    with _connect(db_path) as connection:
        device = _device_for_token(connection, device_token)
        if device is None:
            return False
        connection.execute(
            "DELETE FROM companion_devices WHERE id = ?",
            (device["id"],),
        )
    return True


def list_devices(db_path: Path | str) -> list[dict[str, Any]]:
    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, name, endpoint, enabled, created_at, updated_at,
                   last_seen_at, last_success_at, last_error
            FROM companion_devices
            ORDER BY created_at DESC
            """
        ).fetchall()
    devices = []
    for row in rows:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["push_service"] = urlparse(str(item.pop("endpoint"))).hostname or ""
        devices.append(item)
    return devices


def revoke_device(db_path: Path | str, device_id: str) -> bool:
    with _connect(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM companion_devices WHERE id = ?",
            (str(device_id or ""),),
        )
    return cursor.rowcount > 0


def _sanitize_payment_comment(value: Any) -> str:
    if not isinstance(value, str):
        return ""

    cleaned: list[str] = []
    pending_space = False
    for character in unicodedata.normalize("NFC", value):
        if character.isspace():
            pending_space = bool(cleaned)
            continue
        if unicodedata.category(character).startswith("C") and character != "\u200d":
            continue
        if pending_space:
            cleaned.append(" ")
            pending_space = False
        cleaned.append(character)

    comment = "".join(cleaned).strip()
    if len(comment) > MAX_PUSH_COMMENT_CHARS:
        comment = comment[:MAX_PUSH_COMMENT_CHARS].rstrip()
    return comment.rstrip("\u200d")


def _payment_comment(item: dict[str, Any]) -> str:
    payer_note = _sanitize_payment_comment(item.get("payer_note"))
    if payer_note:
        return payer_note

    method = str(item.get("method") or "").strip().lower()
    if method in {"lightning_address", "lnurl"}:
        return _sanitize_payment_comment(item.get("memo"))
    return ""


def queue_settled_payment(
    db_path: Path | str,
    item: dict[str, Any],
    *,
    now: int | None = None,
) -> bool:
    if item.get("direction") != "incoming" or item.get("status") != "settled":
        return False
    payment_hash = str(item.get("payment_hash") or "").strip()
    if not payment_hash:
        return False
    timestamp = int(time.time()) if now is None else int(now)
    event_id = secrets.token_urlsafe(16)
    payload_data = {
        "version": 1,
        "event_id": event_id,
        "type": "payment_received",
        "amount_sat": max(0, int(item.get("amount_sat") or 0)),
        "method": str(item.get("method") or "lightning")[:40],
        "payment_type": str(item.get("type") or "payment")[:40],
    }
    comment = _payment_comment(item)
    if comment:
        payload_data["comment"] = comment
    payload = json.dumps(
        payload_data,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO companion_push_events(
                id, payment_hash, payload, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (event_id, payment_hash, payload, timestamp),
        )
        if cursor.rowcount == 0:
            return False
        connection.execute(
            """
            INSERT OR IGNORE INTO companion_push_deliveries(
                event_id, device_id, status, attempts, next_attempt_at
            )
            SELECT ?, id, 'pending', 0, ?
            FROM companion_devices
            WHERE enabled = 1
            """,
            (event_id, timestamp),
        )
        connection.execute(
            """
            DELETE FROM companion_push_events
            WHERE created_at < ?
              AND NOT EXISTS (
                  SELECT 1 FROM companion_push_deliveries
                  WHERE companion_push_deliveries.event_id = companion_push_events.id
                    AND companion_push_deliveries.status IN ('pending', 'retry')
              )
            """,
            (timestamp - 7 * 24 * 60 * 60,),
        )
    return True


def _exception_status(error: BaseException) -> int | None:
    response = getattr(error, "response", None)
    for attribute in ("status", "status_code"):
        value = getattr(response, attribute, None)
        if isinstance(value, int):
            return value
    return None


def _retry_delay(attempts: int) -> int:
    return min(15 * (2 ** max(0, min(attempts - 1, 8))), 60 * 60)


async def dispatch_due(
    db_path: Path | str,
    *,
    vapid_private_key: str,
    vapid_subject: str,
    limit: int = 20,
    sender: Callable[..., Awaitable[Any]] = secure_webpush_async,
    now: int | None = None,
) -> int:
    timestamp = int(time.time()) if now is None else int(now)
    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT d.event_id, d.device_id, d.attempts, e.payload,
                   c.endpoint, c.p256dh, c.auth
            FROM companion_push_deliveries d
            JOIN companion_push_events e ON e.id = d.event_id
            JOIN companion_devices c ON c.id = d.device_id
            WHERE d.status IN ('pending', 'retry')
              AND d.next_attempt_at <= ?
              AND c.enabled = 1
            ORDER BY d.next_attempt_at, e.created_at
            LIMIT ?
            """,
            (timestamp, max(1, min(int(limit), 100))),
        ).fetchall()

    delivered = 0
    for row in rows:
        attempts = int(row["attempts"]) + 1
        try:
            await sender(
                subscription_info={
                    "endpoint": row["endpoint"],
                    "keys": {
                        "p256dh": row["p256dh"],
                        "auth": row["auth"],
                    },
                },
                data=row["payload"],
                vapid_private_key=vapid_private_key,
                vapid_claims={"sub": vapid_subject},
                ttl=PUSH_TTL_SECONDS,
                timeout=15,
                headers={"Urgency": "high"},
            )
        except Exception as error:
            status_code = _exception_status(error)
            detail = type(error).__name__
            if isinstance(error, WebPushException):
                detail = "WebPush delivery failed"
            unsafe_endpoint = isinstance(error, UnsafePushEndpointError)
            redirected = status_code is not None and 300 <= status_code < 400
            permanent = (
                unsafe_endpoint
                or redirected
                or status_code in {400, 404, 410}
                or attempts >= MAX_PUSH_ATTEMPTS
            )
            with _connect(db_path) as connection:
                connection.execute(
                    """
                    UPDATE companion_push_deliveries
                    SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?
                    WHERE event_id = ? AND device_id = ?
                    """,
                    (
                        "dead" if permanent else "retry",
                        attempts,
                        timestamp + _retry_delay(attempts),
                        detail,
                        row["event_id"],
                        row["device_id"],
                    ),
                )
                if unsafe_endpoint or redirected or status_code in {400, 404, 410}:
                    connection.execute(
                        """
                        UPDATE companion_devices
                        SET enabled = 0, updated_at = ?, last_error = ?
                        WHERE id = ?
                        """,
                        (timestamp, detail, row["device_id"]),
                    )
            continue

        with _connect(db_path) as connection:
            connection.execute(
                """
                UPDATE companion_push_deliveries
                SET status = 'delivered', attempts = ?, delivered_at = ?,
                    last_error = NULL
                WHERE event_id = ? AND device_id = ?
                """,
                (attempts, timestamp, row["event_id"], row["device_id"]),
            )
            connection.execute(
                """
                UPDATE companion_devices
                SET last_success_at = ?, updated_at = ?, last_error = NULL
                WHERE id = ?
                """,
                (timestamp, timestamp, row["device_id"]),
            )
        delivered += 1
    return delivered
