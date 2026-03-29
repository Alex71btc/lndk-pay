from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import websockets

from .nwc import load_connections

_nwc_tasks: dict[str, asyncio.Task] = {}
_nwc_started = False
_nwc_runtime_lock = asyncio.Lock()


def _build_subscription_id(conn: dict[str, Any]) -> str:
    return f"nwc_{conn.get('id', 'unknown')}"


def _build_info_event() -> dict[str, Any]:
    return {
        "kind": 13194,
        "created_at": int(time.time()),
        "tags": [],
        "content": "get_info get_balance pay_invoice",
    }


def _extract_first_p_tag(tags: list[Any]) -> str:
    for tag in tags or []:
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p":
            return str(tag[1] or "").strip().lower()
    return ""


def _find_matching_connection(event_pubkey: str, wallet_service_pubkey: str) -> dict[str, Any] | None:
    event_pubkey = (event_pubkey or "").strip().lower()
    wallet_service_pubkey = (wallet_service_pubkey or "").strip().lower()

    for conn in load_connections():
        if not bool(conn.get("enabled", True)):
            continue
        if str(conn.get("wallet_service_pubkey") or "").strip().lower() != wallet_service_pubkey:
            continue
        if str(conn.get("client_pubkey") or "").strip().lower() == event_pubkey:
            return conn
    return None


def _get_server_privkey() -> str:
    from .app import _get_secret, _get_setting

    return (
        _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or _get_setting("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()


def _build_nwc_success_content(result_type: str, result: dict[str, Any]) -> str:
    payload = {
        "result_type": result_type,
        "error": None,
        "result": result,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _build_nwc_error_content(code: str, message: str) -> str:
    payload = {
        "result_type": None,
        "error": {
            "code": code,
            "message": message,
        },
        "result": None,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


async def _send_nwc_response_event(
    ws,
    request_event: dict[str, Any],
    plaintext_content: str,
) -> None:
    from .app import _nip04_encrypt, _sign_nostr_event

    request_pubkey = str(request_event.get("pubkey") or "").strip().lower()
    request_event_id = str(request_event.get("id") or "").strip()
    server_privkey = _get_server_privkey()

    if not server_privkey:
        raise ValueError("No nostr server private key configured")

    encrypted_content = _nip04_encrypt(server_privkey, request_pubkey, plaintext_content)

    response_event = {
        "kind": 23195,
        "created_at": int(time.time()),
        "tags": [
            ["p", request_pubkey],
            ["e", request_event_id],
        ],
        "content": encrypted_content,
    }

    signed = _sign_nostr_event(response_event)
    await ws.send(json.dumps(["EVENT", signed]))

    print(
        f"[NWC] response sent: request_event_id={request_event_id} response_event_id={signed.get('id')}",
        flush=True,
    )


async def _send_nwc_success(
    ws,
    request_event: dict[str, Any],
    result_type: str,
    result: dict[str, Any],
) -> None:
    content = _build_nwc_success_content(result_type, result)
    await _send_nwc_response_event(ws, request_event, content)

async def _send_nwc_error(
    ws,
    request_event: dict[str, Any],
    code: str,
    message: str,
) -> None:
    content = _build_nwc_error_content(code, message)
    await _send_nwc_response_event(ws, request_event, content)


async def _publish_nwc_info_event(ws, conn: dict[str, Any]) -> None:
    from .app import _sign_nostr_event

    event = _build_info_event()
    signed = _sign_nostr_event(event)

    await ws.send(json.dumps(["EVENT", signed]))
    print(
        f"[NWC] published info event: {conn.get('name')} event_id={signed.get('id')}",
        flush=True,
    )


async def _send_nwc_subscription(ws, conn: dict[str, Any]) -> None:
    sub_id = _build_subscription_id(conn)
    wallet_service_pubkey = str(conn.get("wallet_service_pubkey") or "").strip().lower()

    req = [
        "REQ",
        sub_id,
        {
            "kinds": [23194],
            "#p": [wallet_service_pubkey],
        },
    ]

    await ws.send(json.dumps(req))
    print(
        f"[NWC] subscribed: {conn.get('name')} "
        f"sub_id={sub_id} wallet_service_pubkey={wallet_service_pubkey}",
        flush=True,
    )


async def _handle_request_event(ws, conn: dict[str, Any], event: dict[str, Any]) -> None:
    from .app import _nip04_decrypt, _pay_bolt11_invoice
    import bolt11

    event_id = str(event.get("id") or "")
    event_pubkey = str(event.get("pubkey") or "").strip().lower()
    tags = event.get("tags") or []
    content = str(event.get("content") or "")

    wallet_service_pubkey = _extract_first_p_tag(tags)
    if not wallet_service_pubkey:
        print(f"[NWC] request {event_id}: missing p-tag", flush=True)
        await _send_nwc_error(ws, event, "INVALID_REQUEST", "Missing p-tag")
        return

    matched = _find_matching_connection(event_pubkey, wallet_service_pubkey)
    if not matched:
        print(
            f"[NWC] request {event_id}: no matching enabled connection for client={event_pubkey}",
            flush=True,
        )
        await _send_nwc_error(ws, event, "UNAUTHORIZED", "No matching enabled connection")
        return

    server_privkey = _get_server_privkey()
    if not server_privkey:
        print(f"[NWC] request {event_id}: missing server private key", flush=True)
        await _send_nwc_error(ws, event, "INTERNAL", "Missing server private key")
        return

    try:
        plaintext = _nip04_decrypt(server_privkey, event_pubkey, content)
    except Exception as exc:
        print(f"[NWC] request {event_id}: decrypt failed: {exc}", flush=True)
        await _send_nwc_error(ws, event, "DECRYPT_FAILED", str(exc))
        return

    print(f"[NWC] request {event_id}: decrypted={plaintext[:500]}", flush=True)

    try:
        payload = json.loads(plaintext)
    except Exception as exc:
        print(f"[NWC] request {event_id}: invalid json after decrypt: {exc}", flush=True)
        await _send_nwc_error(ws, event, "INVALID_REQUEST", f"Invalid JSON: {exc}")
        return

    method = str(payload.get("method") or "").strip()
    params = payload.get("params") or {}

    print(
        f"[NWC] request {event_id}: matched_connection={matched.get('name')} method={method} params={params}",
        flush=True,
    )

    permissions = matched.get("permissions") or {}
    limits = matched.get("limits") or {}

    if method == "pay_invoice":
        if not bool(permissions.get("pay_invoice", False)):
            await _send_nwc_error(ws, event, "RESTRICTED", "pay_invoice not allowed")
            return

        invoice = str(params.get("invoice") or "").strip()
        if not invoice:
            await _send_nwc_error(ws, event, "INVALID_REQUEST", "Missing invoice")
            return

        max_payment_sat = int(limits.get("max_payment_sat") or 0)

        try:
            decoded = bolt11.decode(invoice)
        except Exception as exc:
            print(f"[NWC] request {event_id}: invoice decode failed: {exc}", flush=True)
            await _send_nwc_error(ws, event, "INVALID_REQUEST", f"Invalid invoice: {exc}")
            return

        invoice_sat = 0
        try:
            amount_msat = getattr(decoded, "amount_msat", None)
            amount = getattr(decoded, "amount", None)

            if amount_msat is not None:
                invoice_sat = int(amount_msat) // 1000
            elif amount is not None:
                invoice_sat = int(amount)
        except Exception:
            invoice_sat = 0

        if invoice_sat <= 0:
            await _send_nwc_error(ws, event, "INVALID_REQUEST", "Invoice amount missing or invalid")
            return

        if max_payment_sat > 0 and invoice_sat > max_payment_sat:
            msg = f"Invoice amount {invoice_sat} sats exceeds connection limit of {max_payment_sat} sats"
            print(f"[NWC] request {event_id}: limit exceeded: {msg}", flush=True)
            await _send_nwc_error(ws, event, "RESTRICTED", msg)
            return

        try:
            pay_result = await _pay_bolt11_invoice(payment_request=invoice)
        except Exception as exc:
            print(f"[NWC] request {event_id}: payment failed: {exc}", flush=True)
            await _send_nwc_error(ws, event, "PAYMENT_FAILED", str(exc))
            return

        result: dict[str, Any] = {}
        if isinstance(pay_result, dict):
            payment_preimage = pay_result.get("payment_preimage")
            payment_hash = pay_result.get("payment_hash")
            fee_sat = pay_result.get("fee_sat")

            if payment_preimage:
                result["preimage"] = str(payment_preimage)
            if payment_hash:
                result["payment_hash"] = str(payment_hash)
            if fee_sat is not None:
                result["fees_paid"] = int(fee_sat) * 1000

        # --- budget check ---
        amount_sat = decoded_invoice.get("amount_sat") if "decoded_invoice" in locals() else None
        if amount_sat:
            ok, err = _check_and_update_budget(conn, amount_sat)
            if not ok:
                print(f"[NWC] request {event_id}: {err}", flush=True)
                await _send_nwc_error(ws, event, "QUOTA_EXCEEDED", err)
                return

        print(f"[NWC] request {event_id}: payment success result={result}", flush=True)
        await _send_nwc_success(ws, event, "pay_invoice", result)
        return

    if method == "get_info":
        if not bool(permissions.get("get_info", False)):
            await _send_nwc_error(ws, event, "RESTRICTED", "get_info not allowed")
            return

        result = {
            "alias": "BOLT12 Pay",
            "network": "mainnet",
            "block_height": 0,
            "methods": ["pay_invoice", "get_info", "get_balance"],
        }
        await _send_nwc_success(ws, event, "get_info", result)
        return

    if method == "get_balance":
        if not bool(permissions.get("get_balance", False)):
            await _send_nwc_error(ws, event, "RESTRICTED", "get_balance not allowed")
            return

        result = {
            "balance": 0
        }
        await _send_nwc_success(ws, event, "get_balance", result)
        return

    await _send_nwc_error(ws, event, "NOT_IMPLEMENTED", f"Unsupported method: {method}")


async def handle_nwc_message(ws, conn: dict[str, Any], msg: str) -> None:
    try:
        data = json.loads(msg)
    except Exception:
        print(f"[NWC] non-json message on {conn.get('name')}: {msg[:300]}", flush=True)
        return

    if not isinstance(data, list) or not data:
        print(f"[NWC] unexpected message format on {conn.get('name')}: {data!r}", flush=True)
        return

    msg_type = data[0]

    if msg_type == "EVENT":
        if len(data) < 3 or not isinstance(data[2], dict):
            print(f"[NWC] malformed EVENT on {conn.get('name')}: {data!r}", flush=True)
            return

        sub_id = data[1]
        event = data[2]

        event_id = str(event.get("id") or "")
        pubkey = str(event.get("pubkey") or "").strip().lower()
        kind = event.get("kind")
        tags = event.get("tags") or []
        content = str(event.get("content") or "")

        print(
            f"[NWC] EVENT on {conn.get('name')}: "
            f"sub_id={sub_id} kind={kind} event_id={event_id} pubkey={pubkey}",
            flush=True,
        )

        expected_client_pubkey = str(conn.get("client_pubkey") or "").strip().lower()
        if pubkey != expected_client_pubkey:
            print(
                f"[NWC] ignoring EVENT on {conn.get('name')}: "
                f"unexpected client pubkey {pubkey} != {expected_client_pubkey}",
                flush=True,
            )
            return

        print(
            f"[NWC] accepted request event on {conn.get('name')}: "
            f"tags={tags} content_preview={content[:300]}",
            flush=True,
        )

        await _handle_request_event(ws, conn, event)
        return

    if msg_type == "EOSE":
        print(f"[NWC] EOSE on {conn.get('name')}: {data!r}", flush=True)
        return

    if msg_type == "NOTICE":
        print(f"[NWC] NOTICE on {conn.get('name')}: {data!r}", flush=True)
        return

    if msg_type == "OK":
        print(f"[NWC] OK on {conn.get('name')}: {data!r}", flush=True)
        return

    print(f"[NWC] unhandled relay message on {conn.get('name')}: {data!r}", flush=True)



def _now_ts():
    import time
    return int(time.time())


def _period_key(period: str):
    import datetime
    now = datetime.datetime.utcnow()

    if period == "day":
        return now.strftime("%Y-%m-%d")
    if period == "week":
        return f"{now.year}-W{now.isocalendar().week}"
    if period == "month":
        return now.strftime("%Y-%m")

    return "unknown"


def _check_and_update_budget(conn: dict, amount_sat: int) -> tuple[bool, str | None]:
    limits = conn.get("limits", {}) or {}
    usage = conn.setdefault("usage", {})

    # single payment limit
    max_single = limits.get("max_payment_sat")
    if max_single and amount_sat > max_single:
        return False, f"Invoice amount {amount_sat} sats exceeds single payment limit of {max_single} sats"

    for period in ["day", "week", "month"]:
        limit_key = f"{period}_budget_sat"
        limit_val = limits.get(limit_key)
        if not limit_val:
            continue

        period_key = _period_key(period)
        period_usage = usage.setdefault(period, {})
        current = period_usage.get(period_key, 0)

        if current + amount_sat > limit_val:
            return False, f"{period} budget exceeded ({current + amount_sat} > {limit_val} sats)"

    # update usage
    for period in ["day", "week", "month"]:
        limit_key = f"{period}_budget_sat"
        if not limits.get(limit_key):
            continue

        period_key = _period_key(period)
        usage.setdefault(period, {})
        usage[period][period_key] = usage[period].get(period_key, 0) + amount_sat

    return True, None

async def nwc_connection_loop(conn: dict[str, Any]) -> None:
    relay = str(conn.get("relay_url") or "").strip()
    name = str(conn.get("name") or "NWC Connection").strip()

    if not relay:
        print(f"[NWC] skipping {name}: no relay_url configured", flush=True)
        return

    while True:
        try:
            print(f"[NWC] connecting: {name} -> {relay}", flush=True)
            async with websockets.connect(relay, ping_interval=20, ping_timeout=20) as ws:
                print(f"[NWC] connected: {name} -> {relay}", flush=True)

                await _publish_nwc_info_event(ws, conn)
                await _send_nwc_subscription(ws, conn)

                while True:
                    msg = await ws.recv()
                    await handle_nwc_message(ws, conn, msg)

        except Exception as e:
            print(f"[NWC] reconnecting {name} ({relay}) after error: {e}", flush=True)
            await asyncio.sleep(5)


async def _stop_all_nwc_tasks() -> None:
    global _nwc_tasks

    for conn_id, task in list(_nwc_tasks.items()):
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    _nwc_tasks = {}


async def _start_nwc_tasks() -> None:
    global _nwc_tasks

    try:
        connections = load_connections()
    except Exception as e:
        print(f"[NWC] failed to load connections: {e}", flush=True)
        return

    print(f"[NWC] loaded connections: {len(connections)}", flush=True)

    enabled = [c for c in connections if bool(c.get("enabled", True))]
    print(f"[NWC] enabled connections: {len(enabled)}", flush=True)

    if not enabled:
        print("[NWC] no enabled connections, runtime idle", flush=True)
        return

    for conn in enabled:
        conn_id = str(conn.get("id") or "")
        print(
            f"[NWC] scheduling connection: "
            f"name={conn.get('name')} relay={conn.get('relay_url')} client_pubkey={conn.get('client_pubkey')}",
            flush=True,
        )
        task = asyncio.create_task(nwc_connection_loop(conn))
        if conn_id:
            _nwc_tasks[conn_id] = task


async def reload_nwc_runtime() -> None:
    async with _nwc_runtime_lock:
        print("[NWC] reload requested", flush=True)
        await _stop_all_nwc_tasks()
        await _start_nwc_tasks()
        print("[NWC] reload complete", flush=True)


async def start_nwc_runtime() -> None:
    print("[NWC] runtime starting (clean)...", flush=True)
    async with _nwc_runtime_lock:
        await _stop_all_nwc_tasks()
        await _start_nwc_tasks()

