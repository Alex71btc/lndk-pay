from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import time
import unicodedata
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from py_vapid import Vapid
from pywebpush import WebPushException, webpush_async


PAIRING_TTL_SECONDS = 10 * 60
BROWSER_ACTION_TTL_SECONDS = 10 * 60
BROWSER_ENVELOPE_VERSION = 1
BROWSER_ENVELOPE_INFO = b"bolt12-pay/browser-action/v1"
PUSH_TTL_SECONDS = 24 * 60 * 60
MAX_PUSH_ATTEMPTS = 12
VAPID_PRIVATE_KEY_FIELD = "companion_vapid_private_key"
MAX_PUSH_COMMENT_CHARS = 160
PUSH_ENRICHMENT_DELAY_SECONDS = 0


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



async def send_pairing_confirmation(
    *,
    pairing_token: str,
    device_token: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    vapid_private_key: str,
    vapid_subject: str,
    sender: Callable[..., Awaitable[Any]] = secure_webpush_async,
) -> None:
    """Send the device credential only through encrypted WebPush."""
    subscription = validate_subscription(endpoint, p256dh, auth)

    if not pairing_token or not device_token:
        raise ValueError("Missing pairing credentials")

    payload = json.dumps(
        {
            "version": 1,
            "type": "pairing_confirmed",
            "pairing_token": pairing_token,
            "device_token": device_token,
        },
        separators=(",", ":"),
    )

    await sender(
        subscription_info={
            "endpoint": subscription["endpoint"],
            "keys": {
                "p256dh": subscription["p256dh"],
                "auth": subscription["auth"],
            },
        },
        data=payload,
        vapid_private_key=vapid_private_key,
        vapid_claims={"sub": vapid_subject},
        ttl=600,
        timeout=15,
        headers={"Urgency": "high"},
    )


async def send_browser_action_confirmation(
    *,
    action_type: str,
    action_nonce: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    vapid_private_key: str,
    vapid_subject: str,
    sender: Callable[..., Awaitable[Any]] = secure_webpush_async,
) -> None:
    """Confirm a browser-authorized renewal or revocation over WebPush."""
    if action_type not in {"subscription_updated", "device_revoked"}:
        raise ValueError("Invalid browser action confirmation")
    if not _valid_capability(action_nonce):
        raise ValueError("Invalid browser action nonce")

    subscription = validate_subscription(endpoint, p256dh, auth)
    payload = json.dumps(
        {
            "version": 1,
            "type": action_type,
            "action_nonce": action_nonce,
        },
        separators=(",", ":"),
    )

    await sender(
        subscription_info={
            "endpoint": subscription["endpoint"],
            "keys": {
                "p256dh": subscription["p256dh"],
                "auth": subscription["auth"],
            },
        },
        data=payload,
        vapid_private_key=vapid_private_key,
        vapid_claims={"sub": vapid_subject},
        ttl=600,
        timeout=15,
        headers={"Urgency": "high"},
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

            CREATE TABLE IF NOT EXISTS companion_browser_actions (
                nonce_hash TEXT PRIMARY KEY,
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


def _valid_capability(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 32 <= len(value) <= 200
        and re.fullmatch(r"[A-Za-z0-9_-]+", value)
    )


def _decode_base64url(value: str, label: str, *, max_length: int = 200) -> bytes:
    if not value or len(value) > max_length:
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


def decrypt_browser_action(
    envelope: str,
    vapid_private_key: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Decrypt and validate an Android-to-browser action envelope."""
    if (
        not isinstance(envelope, str)
        or not 140 <= len(envelope) <= 6000
        or re.fullmatch(r"[A-Za-z0-9_-]+", envelope) is None
    ):
        raise ValueError("Invalid encrypted browser action")

    try:
        packed = _decode_base64url(
            envelope, "browser action", max_length=6000
        )
        if len(packed) < 1 + 65 + 16 + 12 + 16:
            raise ValueError("Invalid encrypted browser action")
        if packed[0] != BROWSER_ENVELOPE_VERSION:
            raise ValueError("Unsupported encrypted browser action")

        ephemeral_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), packed[1:66]
        )
        salt = packed[66:82]
        nonce = packed[82:94]
        ciphertext = packed[94:]

        private_bytes = _decode_base64url(
            str(vapid_private_key or ""), "VAPID private key"
        )
        if len(private_bytes) != 32:
            raise ValueError("Invalid VAPID private key")
        private_value = int.from_bytes(private_bytes, "big")
        private_key = ec.derive_private_key(private_value, ec.SECP256R1())
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_key)
        action_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=BROWSER_ENVELOPE_INFO,
        ).derive(shared_secret)
        plaintext = AESGCM(action_key).decrypt(
            nonce,
            ciphertext,
            BROWSER_ENVELOPE_INFO,
        )
        payload = json.loads(plaintext.decode("utf-8"))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Invalid encrypted browser action") from exc

    if not isinstance(payload, dict):
        raise ValueError("Invalid encrypted browser action")

    operation = payload.get("operation")
    required = {
        "pair": {
            "operation", "issued_at", "action_nonce", "pairing_token",
            "device_name", "endpoint", "p256dh", "auth",
        },
        "renew": {
            "operation", "issued_at", "action_nonce", "device_token",
            "endpoint", "p256dh", "auth",
        },
        "revoke": {
            "operation", "issued_at", "action_nonce", "device_token",
        },
    }.get(operation)
    if required is None or set(payload) != required:
        raise ValueError("Invalid encrypted browser action")

    timestamp = int(time.time()) if now is None else int(now)
    issued_at = payload.get("issued_at")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at > timestamp + 60
        or issued_at < timestamp - BROWSER_ACTION_TTL_SECONDS
    ):
        raise ValueError("Encrypted browser action expired")
    if not _valid_capability(payload.get("action_nonce")):
        raise ValueError("Invalid encrypted browser action")

    for key in required - {"issued_at"}:
        if not isinstance(payload.get(key), str) or not payload[key]:
            raise ValueError("Invalid encrypted browser action")
    if "pairing_token" in payload and not _valid_capability(payload["pairing_token"]):
        raise ValueError("Invalid encrypted browser action")
    if "device_token" in payload and not _valid_capability(payload["device_token"]):
        raise ValueError("Invalid encrypted browser action")
    if len(str(payload.get("device_name", ""))) > 80:
        raise ValueError("Invalid encrypted browser action")
    if len(str(payload.get("endpoint", ""))) > 1000:
        raise ValueError("Invalid encrypted browser action")
    if len(str(payload.get("p256dh", ""))) > 200:
        raise ValueError("Invalid encrypted browser action")
    if len(str(payload.get("auth", ""))) > 200:
        raise ValueError("Invalid encrypted browser action")

    return payload


def claim_browser_action(
    db_path: Path | str,
    action_nonce: str,
    *,
    now: int | None = None,
) -> None:
    if not _valid_capability(action_nonce):
        raise ValueError("Invalid browser action nonce")
    timestamp = int(time.time()) if now is None else int(now)
    nonce_hash = _hash_token(action_nonce)
    try:
        with _connect(db_path) as connection:
            connection.execute(
                "DELETE FROM companion_browser_actions WHERE expires_at < ?",
                (timestamp,),
            )
            connection.execute(
                """
                INSERT INTO companion_browser_actions(
                    nonce_hash, created_at, expires_at
                ) VALUES (?, ?, ?)
                """,
                (nonce_hash, timestamp, timestamp + BROWSER_ACTION_TTL_SECONDS),
            )
    except sqlite3.IntegrityError as exc:
        raise PermissionError("Browser action was already used") from exc


def release_browser_action(db_path: Path | str, action_nonce: str) -> None:
    if not _valid_capability(action_nonce):
        return
    with _connect(db_path) as connection:
        connection.execute(
            "DELETE FROM companion_browser_actions WHERE nonce_hash = ?",
            (_hash_token(action_nonce),),
        )


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
    include_rollback: bool = False,
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
            "SELECT * FROM companion_devices WHERE endpoint = ?",
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

    result = {
        "id": device_id,
        "name": device_name,
        "device_token": device_token,
        "created_at": created_at,
    }
    if include_rollback:
        result["_rollback"] = dict(existing) if existing is not None else None
    return result


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
    include_rollback: bool = False,
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
    result = {"id": device["id"], "name": device["name"], "enabled": True}
    if include_rollback:
        result["_rollback"] = dict(device)
    return result


def rollback_device_change(
    db_path: Path | str,
    *,
    current_device_token: str,
    previous: dict[str, Any] | None,
) -> bool:
    """Undo only the device row written with current_device_token."""
    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        current = _device_for_token(connection, current_device_token)
        if current is None:
            return False
        if previous is None:
            cursor = connection.execute(
                "DELETE FROM companion_devices WHERE id = ? AND token_hash = ?",
                (current["id"], current["token_hash"]),
            )
            return cursor.rowcount > 0

        if str(previous.get("id") or "") != str(current["id"]):
            return False
        cursor = connection.execute(
            """
            UPDATE companion_devices
            SET name = ?, token_hash = ?, endpoint = ?, p256dh = ?, auth = ?,
                enabled = ?, created_at = ?, updated_at = ?, last_seen_at = ?,
                last_success_at = ?, last_error = ?
            WHERE id = ? AND token_hash = ?
            """,
            (
                previous["name"],
                previous["token_hash"],
                previous["endpoint"],
                previous["p256dh"],
                previous["auth"],
                previous["enabled"],
                previous["created_at"],
                previous["updated_at"],
                previous["last_seen_at"],
                previous["last_success_at"],
                previous["last_error"],
                current["id"],
                current["token_hash"],
            ),
        )
    return cursor.rowcount > 0


def device_subscription(
    db_path: Path | str,
    device_token: str,
) -> dict[str, Any] | None:
    with _connect(db_path) as connection:
        device = _device_for_token(connection, device_token)
        if device is None:
            return None
        return {
            "id": device["id"],
            "name": device["name"],
            "endpoint": device["endpoint"],
            "p256dh": device["p256dh"],
            "auth": device["auth"],
        }


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


def _payment_comment_details(item: dict[str, Any]) -> tuple[str, str]:
    payer_note = _sanitize_payment_comment(item.get("payer_note"))
    if payer_note:
        return payer_note, "payer_note"

    method = str(item.get("method") or "").strip().lower()
    if method in {"lightning_address", "lnurl"}:
        comment = _sanitize_payment_comment(item.get("memo"))
        return (comment, "lnurl_comment") if comment else ("", "")
    if method == "keysend":
        comment = _sanitize_payment_comment(item.get("memo"))
        return (comment, "keysend_message") if comment else ("", "")
    if method == "bolt11_alias_fallback":
        memo = str(item.get("memo") or "")
        prefix = "BOLT11 alias fallback:"
        if memo.startswith(prefix):
            description = _sanitize_payment_comment(memo[len(prefix):])
            if description:
                return description, "invoice_description"
    return "", ""


def _payment_comment(item: dict[str, Any]) -> str:
    return _payment_comment_details(item)[0]


def _payment_payload(event_id: str, item: dict[str, Any]) -> str:
    payload_data = {
        "version": 1,
        "event_id": event_id,
        "type": "payment_received",
        "amount_sat": max(0, int(item.get("amount_sat") or 0)),
        "method": str(item.get("method") or "lightning")[:40],
        "payment_type": str(item.get("type") or "payment")[:40],
    }
    comment, comment_source = _payment_comment_details(item)
    if comment:
        payload_data["comment"] = comment
        payload_data["comment_source"] = comment_source
    return json.dumps(
        payload_data,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _initial_dispatch_delay(item: dict[str, Any]) -> int:
    method = str(item.get("method") or "").strip().lower()
    if not _payment_comment(item) and method in {"bolt11", "bolt12"}:
        return PUSH_ENRICHMENT_DELAY_SECONDS
    return 0


def queue_settled_payment(
    db_path: Path | str,
    item: dict[str, Any],
    *,
    now: int | None = None,
    allow_create: bool = True,
) -> bool:
    if item.get("direction") != "incoming" or item.get("status") != "settled":
        return False
    payment_hash = str(item.get("payment_hash") or "").strip()
    if not payment_hash:
        return False
    timestamp = int(time.time()) if now is None else int(now)
    event_id = secrets.token_urlsafe(16)
    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """
            SELECT id, payload FROM companion_push_events
            WHERE payment_hash = ?
            """,
            (payment_hash,),
        ).fetchone()
        if existing is not None:
            event_id = str(existing["id"])
            payload = _payment_payload(event_id, item)
            if payload == existing["payload"]:
                return False
            cursor = connection.execute(
                """
                UPDATE companion_push_events
                SET payload = ?
                WHERE id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM companion_push_deliveries
                      WHERE companion_push_deliveries.event_id = companion_push_events.id
                        AND (
                            status != 'pending'
                            OR attempts != 0
                            OR next_attempt_at <= ?
                        )
                  )
                """,
                (payload, event_id, timestamp),
            )
            return cursor.rowcount > 0

        if not allow_create:
            return False

        payload = _payment_payload(event_id, item)
        connection.execute(
            """
            INSERT INTO companion_push_events(
                id, payment_hash, payload, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (event_id, payment_hash, payload, timestamp),
        )
        next_attempt_at = timestamp + _initial_dispatch_delay(item)
        connection.execute(
            """
            INSERT OR IGNORE INTO companion_push_deliveries(
                event_id, device_id, status, attempts, next_attempt_at
            )
            SELECT ?, id, 'pending', 0, ?
            FROM companion_devices
            WHERE enabled = 1
            """,
            (event_id, next_attempt_at),
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
