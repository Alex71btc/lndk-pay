"""Wallet selection and persistent ownership for invoices, aliases and NWC.

A Phoenixd instance is bound to its node id. Changing transport or credentials
never silently turns existing invoices into invoices of a different wallet.
"""
import asyncio
import base64
import copy
import hashlib
import json
import time
import uuid
import re

import httpx
from fastapi import HTTPException
from backend.phoenixd import PhoenixdClient

LND_ID = "lnd-default"
CONFIG_LOCK = asyncio.Lock()
PAYMENT_LOCK = asyncio.Lock()


def state(cfg):
    return copy.deepcopy(cfg.get("lightning_backend") or {"active": LND_ID, "phoenixd": None})


def public_state(cfg):
    result = state(cfg)
    result.pop("detached_phoenixd", None)
    hidden_aliases = result.pop("hidden_phoenixd_aliases", [])
    phoenix = result.get("phoenixd")
    if phoenix:
        phoenix["password_set"] = bool(phoenix.pop("password", ""))
        phoenix["alias_pages_hidden"] = phoenix.get("id") in hidden_aliases
    return result


def connected_phoenixd(cfg):
    instance = (cfg.get("lightning_backend") or {}).get("phoenixd")
    return instance if instance and not instance.get("paused") else None


def can_issue_public_invoice(cfg, backend_id):
    if backend_id == LND_ID:
        return True
    phoenix = connected_phoenixd(cfg)
    return bool(phoenix and phoenix["id"] == backend_id)


def alias_page_hidden(cfg, alias):
    backend_id = alias.get("backend_id", LND_ID)
    settings = cfg.get("lightning_backend") or {}
    return backend_id in settings.get("hidden_phoenixd_aliases", []) and not can_issue_public_invoice(cfg, backend_id)


def selected(cfg, expected=None):
    settings = state(cfg)
    active = settings.get("active", LND_ID)
    if expected != active and (expected is not None or active != LND_ID):
        raise HTTPException(409, "Lightning backend changed. Reload before continuing.")
    if active == LND_ID:
        return None
    instance = connected_phoenixd(cfg)
    if not instance or instance.get("id") != active:
        raise HTTPException(409, "Lightning backend is not configured")
    return instance


def bound(cfg, backend_id):
    """Resolve a saved object's owner, independently of the current selector."""
    if backend_id == LND_ID:
        return None
    instance = connected_phoenixd(cfg)
    if not instance or instance.get('id') != backend_id:
        raise HTTPException(409, 'The receiving wallet is unavailable; its binding was preserved.')
    return instance


def migrate_history(conn):
    """Transactional migration of the old hash-only key, preserving every column."""
    columns = conn.execute("PRAGMA table_info(tx_history)").fetchall()
    if any(c[1] == "backend_id" for c in columns):
        return
    definitions = []
    for col in columns:
        definition = f'"{col[1]}" {col[2]}'
        if col[3]:
            definition += " NOT NULL"
        if col[4] is not None:
            definition += f" DEFAULT {col[4]}"
        definitions.append(definition)
    definitions.extend([
        "backend_id TEXT NOT NULL DEFAULT 'lnd-default'",
        "PRIMARY KEY (backend_id, direction, payment_hash)",
    ])
    names = ", ".join(f'"{c[1]}"' for c in columns)
    indexes = [row[0] for row in conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='tx_history' AND sql IS NOT NULL"
    ).fetchall()]
    conn.execute("SAVEPOINT backend_migration")
    try:
        conn.execute("CREATE TABLE tx_history_backend_migration (" + ", ".join(definitions) + ")")
        conn.execute(f"INSERT INTO tx_history_backend_migration ({names}) SELECT {names} FROM tx_history")
        conn.execute("DROP TABLE tx_history")
        conn.execute("ALTER TABLE tx_history_backend_migration RENAME TO tx_history")
        for sql in indexes:
            conn.execute(sql)
    except Exception:
        conn.execute("ROLLBACK TO backend_migration")
        raise
    finally:
        conn.execute("RELEASE backend_migration")


async def checked_client(instance):
    try:
        client = PhoenixdClient(instance["url"], instance["password"])
        info = await client.get_info()
    except (ValueError, KeyError, httpx.HTTPError):
        raise HTTPException(502, "Phoenixd connection failed. Check URL and API password.") from None
    node_id = str(info.get("nodeId") or "") if isinstance(info, dict) else ""
    if not re.fullmatch(r"0[23][0-9a-fA-F]{64}", node_id) or node_id != instance.get("node_id", node_id):
        raise HTTPException(409, "Phoenixd node identity changed; existing backend binding was preserved.")
    return client, node_id


async def configure(cfg, payload):
    settings = state(cfg)
    previous = settings.get("phoenixd") or {}
    if previous.get("paused"):
        raise HTTPException(409, "Resume Phoenixd before changing its connection.")
    url = str(payload.get("url", previous.get("url")) or "").strip().rstrip("/")
    if not url:
        raise HTTPException(400, "Enter the Phoenixd server URL.")
    password = payload.get("password") or previous.get("password") or ""
    if not isinstance(password, str):
        raise HTTPException(400, "Invalid API password")
    candidate = {**previous, "url": url, "password": password}
    _, node_id = await checked_client(candidate)
    detached = settings.get("detached_phoenixd", {})
    known_id = detached.get(node_id)
    candidate.update(
        id=previous.get("id") or known_id or "phoenixd-" + uuid.uuid4().hex,
        node_id=node_id,
        revision=previous.get("revision") if previous else uuid.uuid4().hex,
    )
    detached.pop(node_id, None)
    active = payload.get("active", "phoenixd")
    if active not in {"phoenixd", LND_ID, candidate["id"]}:
        raise HTTPException(400, "Invalid Lightning backend")
    updated = {**cfg, "lightning_backend": {
        **settings, "active": LND_ID if active == LND_ID else candidate["id"], "phoenixd": candidate,
    }}
    return updated


def timestamp(value):
    return str(int(value) // 1000) if value is not None else None


def history_item(raw, direction, instance_id):
    payment_hash = str(raw.get("paymentHash") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", payment_hash):
        raise ValueError("Phoenixd history is missing a payment hash")
    status = "settled" if raw.get("isPaid") is True else "pending"
    if direction == "outgoing" and raw.get("completedAt") is not None and status != "settled":
        status = "failed"
    if direction == "incoming" and raw.get("isExpired") and status != "settled":
        status = "expired"
    fees_msat = int(raw.get("fees") or 0)
    amount_sat = (int(raw.get("receivedSat") or 0) if status == "settled" else int(raw.get("requestedSat") or 0)) if direction == "incoming" else max(0, int(raw.get("sent") or 0) - fees_msat // 1000)
    return {
        "backend_id": instance_id, "payment_hash": payment_hash, "direction": direction,
        "type": "invoice" if direction == "incoming" else "payment", "method": "bolt11" if raw.get("invoice") else "bolt12",
        "payer_note": raw.get("payerNote") or "",
        "amount_sat": amount_sat,
        "fee_sat": fees_msat // 1000, "status": status,
        "memo": raw.get("description") or "", "identifier": raw.get("invoice") or "",
        "origin": "api", "created_at": timestamp(raw.get("createdAt")),
        "settled_at": timestamp(raw.get("completedAt")) if status == "settled" else None,
        "raw_json": {**raw, "payment_request": raw.get("invoice") or "",
                     "payment_preimage": raw.get("preimage") or ""},
    }


def payment_failure_detail(result, payment_type):
    # Phoenixd may return payment_failed with HTTP 200. Keep its reason visible
    # instead of reducing invoice-request and routing failures to one message.
    reason = result.get('reason')
    reason = ' '.join(reason.split()) if isinstance(reason, str) else ''
    reason = ''.join(char for char in reason if char.isprintable())[:240]
    suffix = ': ' + reason if reason else ''
    return f'Phoenixd {payment_type} payment failed{suffix}. See Lightning Activity.'


class PhoenixBackend:
    def __init__(self, instance, db_conn, save_item, notify_item=None, require_connected=None):
        self.instance = copy.deepcopy(instance)
        self.db_conn, self.save_item = db_conn, save_item
        self.notify_item = notify_item
        self.require_connected = require_connected

    def existing(self, payment_hash, direction):
        with self.db_conn() as conn:
            row = conn.execute(
                "SELECT * FROM tx_history WHERE backend_id = ? AND direction = ? AND payment_hash = ?",
                (self.instance["id"], direction, payment_hash),
            ).fetchone()
        return dict(row) if row else None

    def store(self, item):
        if self.require_connected:
            self.require_connected()
        old = self.existing(item["payment_hash"], item["direction"])
        if old:
            # Metadata and an invoice's face amount survive unpaid history refreshes.
            for key in ("memo", "identifier", "counterparty", "origin", "created_at", "payer_note", "method"):
                item[key] = old.get(key) or item.get(key)
            if item["status"] == "pending":
                item["amount_sat"] = old["amount_sat"] or item["amount_sat"]
            if old["status"] == "settled" and item["status"] != "settled":
                return False
            comparable = dict(old)
            comparable["raw_json"] = json.loads(comparable.get("raw_json") or "{}")
            if all(comparable.get(k) == v for k, v in item.items()):
                return False
        self.save_item(item)
        if self.notify_item:
            self.notify_item(item, old)
        return True

    async def create(self, amount_sat, memo, expiry, *, description_hash=None, method='bolt11', counterparty=''):
        if not description_hash and len(memo) > 128:
            raise HTTPException(400, "Phoenixd invoice descriptions are limited to 128 characters")
        client, _ = await checked_client(self.instance)
        try:
            kwargs = {'expiry': expiry}
            if description_hash:
                kwargs['description_hash'] = base64.b64decode(description_hash, validate=True).hex()
                if len(kwargs['description_hash']) != 64:
                    raise ValueError('Invalid description hash')
            result = await client.create_invoice(amount_sat, memo, **kwargs)
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, "Phoenixd invoice creation failed") from None
        payment_hash, invoice = result.get("paymentHash"), result.get("serialized")
        if not payment_hash or not invoice:
            raise HTTPException(502, "Phoenixd returned an invalid invoice")
        self.store({
            "backend_id": self.instance["id"], "payment_hash": payment_hash,
            "direction": "incoming", "type": "invoice", "method": method, "origin": "nwc" if method == 'nwc' else "web", "counterparty": counterparty,
            "amount_sat": amount_sat, "status": "pending", "memo": memo,
            "identifier": invoice, "created_at": str(int(time.time())),
            "raw_json": {**result, "payment_request": invoice, "expires_at": int(time.time()) + expiry},
        })
        return {"payment_request": invoice, "payment_hash": payment_hash, "raw": result}

    async def pay(self, invoice, amount_sat=None, *, method="bolt11", counterparty="", origin="web"):
        # Decode locally, so no LND connection or credentials are involved.
        from bolt11 import decode
        try:
            decoded = decode(invoice)
            payment_hash = decoded.payment_hash
            amount = int(decoded.amount_msat or 0) // 1000 or amount_sat
            if decoded.amount_msat and amount_sat is not None and amount_sat * 1000 != int(decoded.amount_msat):
                raise ValueError("Invoice amount mismatch")
            if decoded.has_expired():
                raise ValueError("Invoice expired")
            if not amount or amount < 1:
                raise ValueError("amount required")
        except Exception:
            raise HTTPException(400, "Invalid BOLT11 invoice or missing amount") from None
        async with PAYMENT_LOCK:
            if self.require_connected:
                self.require_connected()
            previous = self.existing(payment_hash, "outgoing")
            if previous and previous["status"] in {"pending", "settled"}:
                raise HTTPException(409, "Payment already submitted. Check Lightning Activity before retrying.")
            client, _ = await checked_client(self.instance)
            item = {
                "backend_id": self.instance["id"], "payment_hash": payment_hash,
                "direction": "outgoing", "type": "payment", "method": method, "counterparty": counterparty, "origin": origin,
                "amount_sat": amount, "status": "pending", "memo": decoded.description or "",
                "identifier": invoice, "created_at": str(int(time.time())),
                "raw_json": {"payment_request": invoice},
            }
            # Persist ownership BEFORE the network call; never retry automatically.
            self.store(item)
            try:
                result = await client.pay_invoice(invoice, amount_sat)
            except (httpx.HTTPError, ValueError):
                raise HTTPException(502, "Phoenixd payment outcome unknown. Check Lightning Activity; do not resend.") from None
            if result.get("reason") and result.get("paymentHash") == payment_hash:
                item.update(status="failed", raw_json={**result, "payment_request": invoice})
                self.store(item)
                raise HTTPException(400, payment_failure_detail(result, 'BOLT11'))
            # A hash alone is NOT confirmation of settlement. Verify the preimage.
            preimage = result.get("paymentPreimage") or result.get("preimage") or ""
            try:
                confirmed = hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == payment_hash
            except (ValueError, TypeError):
                confirmed = False
            if confirmed:
                item.update(status="settled", settled_at=str(int(time.time())),
                            fee_sat=int(result.get("routingFeeSat") or 0),
                            raw_json={**result, "payment_request": invoice, "payment_preimage": preimage})
                self.store(item)
                return {**result, "payment_hash": payment_hash, "payment_preimage": preimage,
                        "fee_sat": item['fee_sat'], "status": "SUCCEEDED"}
            # Query the original instance even if Setup changed during the payment.
            try:
                raw = await client.get_outgoing(payment_hash)
                item = history_item(raw, "outgoing", self.instance["id"])
                if item["payment_hash"] != payment_hash:
                    raise ValueError("Phoenixd returned a different payment hash")
                self.store(item)
            except (httpx.HTTPError, ValueError, TypeError):
                raise HTTPException(502, "Phoenixd payment outcome unknown. Check Lightning Activity; do not resend.") from None
            if item["status"] != "settled":
                raise HTTPException(409, "Phoenixd payment " + item["status"] + ". Check Lightning Activity.")
            return {**raw, "payment_hash": payment_hash, "payment_preimage": raw.get('preimage', ''),
                    "fee_sat": item['fee_sat'], "status": "SUCCEEDED"}

    async def pay_offer(self, offer, amount_sat, message=None, identifier=None):
        # Offers are reusable; only unresolved submissions block the same target.
        legacy_attempt = 'phoenix-attempt-' + hashlib.sha256(offer.encode()).hexdigest()
        async with PAYMENT_LOCK:
            if self.require_connected:
                self.require_connected()
            with self.db_conn() as conn:
                pending = conn.execute(
                    "SELECT payment_hash, raw_json FROM tx_history "
                    "WHERE backend_id=? AND direction='outgoing' AND status='pending' "
                    "AND payment_hash LIKE 'phoenix-attempt-%'",
                    (self.instance['id'],),
                ).fetchall()
            for previous in pending:
                try:
                    previous_offer = json.loads(previous['raw_json'] or '{}').get('offer')
                except (ValueError, TypeError, AttributeError):
                    previous_offer = None
                if previous['payment_hash'] == legacy_attempt or previous_offer == offer:
                    raise HTTPException(409, 'Previous payment outcome unknown. Check Activity before retrying.')
            # Each intentional submission has its own identity. Reusing the
            # offer hash inherited the old failure's timestamp and payer note.
            attempt = 'phoenix-attempt-' + uuid.uuid4().hex
            client, _ = await checked_client(self.instance)
            try:
                await client.decode_offer(offer)
            except (httpx.HTTPError, ValueError):
                raise HTTPException(400, 'Phoenixd could not decode this offer') from None
            item = {'backend_id': self.instance['id'], 'payment_hash': attempt,
                    'direction': 'outgoing', 'type': 'payment', 'method': 'bolt12',
                    'origin': 'web', 'amount_sat': amount_sat, 'status': 'pending',
                    'memo': message or '', 'identifier': identifier or offer,
                    'created_at': str(int(time.time())), 'raw_json': {'offer': offer}}
            self.store(item)
            try:
                result = await client.pay_offer(offer, amount_sat, message)
            except (httpx.HTTPError, ValueError) as exc:
                item['raw_json']['transport_error'] = type(exc).__name__
                if isinstance(exc, httpx.HTTPStatusError):
                    item['raw_json']['http_status'] = exc.response.status_code
                self.store(item)
                raise HTTPException(502, 'Phoenixd payment outcome unknown. Check Activity; do not resend.') from None
            if not isinstance(result, dict):
                raise HTTPException(502, 'Phoenixd payment outcome unknown. Check Activity; do not resend.')
            if result.get('reason'):
                item.update(status='failed', raw_json={**result, 'offer': offer})
                self.store(item)
                raise HTTPException(400, payment_failure_detail(result, 'BOLT12'))
            payment_hash = result.get('paymentHash')
            try:
                confirmed = hashlib.sha256(bytes.fromhex(result.get('paymentPreimage', ''))).hexdigest() == payment_hash
            except (ValueError, TypeError):
                confirmed = False
            if not confirmed:
                raise HTTPException(502, 'Phoenixd payment outcome unknown. Check Activity; do not resend.')
            item.update(payment_hash=payment_hash, status='settled',
                        settled_at=str(int(time.time())), fee_sat=int(result.get('routingFeeSat') or 0),
                        raw_json={**result, 'offer': offer})
            self.store(item)
            with self.db_conn() as conn:
                conn.execute('DELETE FROM tx_history WHERE backend_id=? AND direction=? AND payment_hash=?',
                             (self.instance['id'], 'outgoing', attempt))
                conn.commit()
            return {**result, 'payment_hash': payment_hash, 'status': 'SUCCEEDED'}

    async def sync(self):
        client, _ = await checked_client(self.instance)
        changed = 0
        for direction, listing in (("incoming", client.list_incoming), ("outgoing", client.list_outgoing)):
            offset = 0
            candidates = {}
            while True:
                if self.require_connected:
                    self.require_connected()
                rows = await listing(limit=100, offset=offset)
                if not isinstance(rows, list):
                    raise ValueError("Invalid Phoenixd history response")
                for raw in rows:
                    # Phoenixd also lists on-chain liquidity purchases. This milestone
                    # imports only BOLT11 Lightning payments, never mislabeled on-chain rows.
                    if not raw.get("paymentHash") or (not raw.get("invoice") and raw.get("subType") != "lightning"):
                        continue
                    item = history_item(raw, direction, self.instance["id"])
                    previous = candidates.get(item["payment_hash"])
                    # Like outgoingbyhash: success wins, then pending, then failed.
                    # Older failed attempts must never overwrite a pending retry.
                    priority = {"settled": 3, "pending": 2, "failed": 1, "expired": 1}
                    rank = lambda entry: (priority[entry["status"]], int(entry["created_at"] or 0))
                    if previous is None or rank(item) > rank(previous):
                        candidates[item["payment_hash"]] = item
                if len(rows) < 100:
                    break
                offset += len(rows)
            if self.require_connected:
                self.require_connected()
            for item in candidates.values():
                changed += int(self.store(item))
        return changed
