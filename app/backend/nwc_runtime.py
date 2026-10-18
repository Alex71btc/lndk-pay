from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import re
import time
from pathlib import Path
from typing import Any

import websockets

from .nwc import load_connections, update_nwc_connection_usage

_nwc_tasks: dict[str, asyncio.Task] = {}
_nwc_runtime_lock = asyncio.Lock()
_nwc_request_lock = asyncio.Lock()
_nwc_requests_in_flight: set[str] = set()
_nwc_requests_seen: dict[str, float] = {}
_nwc_requests_seen_loaded = False
_nwc_pending_responses: dict[str, dict[str, Any]] = {}
_nwc_response_ids_by_request: dict[str, str] = {}

NWC_RECONNECT_BASE_SECONDS = 5.0
NWC_RECONNECT_MAX_SECONDS = 300.0
NWC_STABLE_CONNECTION_SECONDS = 30.0
NWC_INITIAL_LOOKBACK_SECONDS = 30
NWC_INFO_REPUBLISH_SECONDS = 60 * 60
NWC_REQUEST_DEDUP_TTL_SECONDS = 24 * 60 * 60
NWC_REQUEST_DEDUP_MAX_ITEMS = 5000
NWC_PENDING_RESPONSE_TTL_SECONDS = 10 * 60
NWC_PENDING_RESPONSE_MAX_ITEMS = 500
NWC_RETRYABLE_RELAY_REJECTION_PREFIXES = {"rate-limited", "error"}
NWC_REQUEST_DEDUP_PATH = Path(
    os.getenv(
        "NWC_REQUEST_DEDUP_PATH",
        str(
            Path(os.getenv("APP_DATA_DIR", "/data"))
            / "config"
            / "nwc_processed_requests.json"
        ),
    )
)


class NwcRelaySubscriptionClosed(ConnectionError):
    """The relay closed the active request subscription."""


class NwcRelayPublishRejected(ConnectionError):
    """The relay rejected a response event that still needs delivery."""


def _log(message: str) -> None:
    print(f"[NWC] {message}", flush=True)


_SENSITIVE_LOG_TOKEN_RE = re.compile(
    r"(?i)(?:[0-9a-f]{24,}|(?:lnbc|lntb|lnbcrt|lno|lnurl|npub|nsec)1[0-9a-z]{16,})"
)


def _short_identifier(value: Any, head: int = 8, tail: int = 6) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    if len(text) <= head + tail + 1:
        return text
    return f"{text[:head]}…{text[-tail:]}"


def _safe_log_text(value: Any, limit: int = 240) -> str:
    text = str(value or "").replace("\n", " ").replace("\r", " ")
    text = _SENSITIVE_LOG_TOKEN_RE.sub(
        lambda match: _short_identifier(match.group(0)),
        text,
    )
    if len(text) > limit:
        text = f"{text[:limit]}…"
    return text


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _build_subscription_id(conn: dict[str, Any]) -> str:
    return f"nwc_{conn.get('id', 'unknown')}"


def _build_relay_subscription_id(relay: str) -> str:
    digest = hashlib.sha256(relay.encode("utf-8")).hexdigest()[:12]
    return f"nwc_relay_{digest}"


def _build_info_event() -> dict[str, Any]:
    return {
        "kind": 13194,
        "created_at": int(time.time()),
        "tags": [],
        "content": (
            "get_info get_balance pay_invoice make_invoice "
            "lookup_invoice list_transactions"
        ),
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
    from .app import _get_secret

    return (
        _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()


# ---------------------------------------------------------------------------
# Budget helpers
# ---------------------------------------------------------------------------

def _current_budget_period_key(period: str) -> str:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    period = (period or "none").strip().lower()

    if period == "day":
        return now.strftime("%Y-%m-%d")
    if period == "week":
        iso = now.isocalendar()
        return f"{iso.year}-W{iso.week:02d}"
    if period == "month":
        return now.strftime("%Y-%m")
    return ""


def _check_budget(
    conn: dict[str, Any],
    amount_sat: int,
) -> tuple[bool, str | None, tuple[str, int] | None]:
    limits = conn.get("limits") or {}
    period = str(limits.get("budget_period") or "none").strip().lower()
    budget_amount_sat = int(limits.get("budget_amount_sat") or 0)

    _log(
        f"budget check: conn={conn.get('name')} period={period} "
        f"budget_amount_sat={budget_amount_sat} amount_sat={amount_sat}"
    )

    if period == "none" or budget_amount_sat <= 0:
        return True, None, None

    period_key = _current_budget_period_key(period)
    usage = conn.get("usage") or {}

    current_period_key = str(usage.get("period_key") or "")
    spent_sat = int(usage.get("spent_sat") or 0)

    if current_period_key != period_key:
        spent_sat = 0

    new_total = spent_sat + int(amount_sat)

    if new_total > budget_amount_sat:
        return (
            False,
            f"Budget exceeded: {new_total} sats > {budget_amount_sat} sats per {period}",
            None,
        )

    return True, None, (period_key, new_total)


def _commit_budget_usage(
    conn: dict[str, Any],
    reservation: tuple[str, int] | None,
) -> None:
    if reservation is None:
        return
    period_key, new_total = reservation
    update_nwc_connection_usage(
        str(conn.get("id") or ""),
        period_key,
        new_total,
    )
    _log(f"budget updated: conn={conn.get('name')} spent_sat={new_total}")



# ---------------------------------------------------------------------------
# Response payload helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Nostr response sending
# ---------------------------------------------------------------------------

def _remove_pending_nwc_response(response_event_id: str) -> None:
    pending = _nwc_pending_responses.pop(response_event_id, None)
    if not pending:
        return

    request_event_id = str(pending.get("request_event_id") or "")
    if _nwc_response_ids_by_request.get(request_event_id) == response_event_id:
        _nwc_response_ids_by_request.pop(request_event_id, None)


def _prune_pending_nwc_responses(now: float) -> None:
    cutoff = now - NWC_PENDING_RESPONSE_TTL_SECONDS
    for response_event_id, pending in list(_nwc_pending_responses.items()):
        if float(pending.get("created_at") or 0) < cutoff:
            _remove_pending_nwc_response(response_event_id)

    overflow = len(_nwc_pending_responses) - NWC_PENDING_RESPONSE_MAX_ITEMS
    if overflow > 0:
        oldest = sorted(
            _nwc_pending_responses.items(),
            key=lambda item: float(item[1].get("created_at") or 0),
        )
        for response_event_id, _ in oldest[:overflow]:
            _remove_pending_nwc_response(response_event_id)


def _register_pending_nwc_response(
    request_event: dict[str, Any],
    signed_response: dict[str, Any],
) -> None:
    request_event_id = str(request_event.get("id") or "").strip()
    response_event_id = str(signed_response.get("id") or "").strip()
    if not request_event_id or not response_event_id:
        return

    previous_response_id = _nwc_response_ids_by_request.get(request_event_id)
    if previous_response_id and previous_response_id != response_event_id:
        _remove_pending_nwc_response(previous_response_id)

    _nwc_pending_responses[response_event_id] = {
        "request_event_id": request_event_id,
        "client_pubkey": str(request_event.get("pubkey") or "").strip().lower(),
        "wallet_service_pubkey": _extract_first_p_tag(request_event.get("tags") or []),
        "signed_event": signed_response,
        "created_at": time.time(),
        "send_count": 0,
    }
    _nwc_response_ids_by_request[request_event_id] = response_event_id
    _prune_pending_nwc_responses(time.time())


def _pending_nwc_response_for_request(
    request_event_id: str,
) -> dict[str, Any] | None:
    _prune_pending_nwc_responses(time.time())
    response_event_id = _nwc_response_ids_by_request.get(request_event_id)
    if not response_event_id:
        return None
    return _nwc_pending_responses.get(response_event_id)


async def _send_pending_nwc_response(
    ws,
    pending: dict[str, Any],
    *,
    retry: bool,
) -> None:
    signed_event = pending.get("signed_event")
    if not isinstance(signed_event, dict):
        return

    await ws.send(json.dumps(["EVENT", signed_event]))
    pending["send_count"] = int(pending.get("send_count") or 0) + 1
    _log(
        f"response {'retried' if retry else 'sent'}: "
        f"request_event_id={_short_identifier(pending.get('request_event_id'))} "
        f"response_event_id={_short_identifier(signed_event.get('id'))} "
        f"send_count={pending['send_count']}"
    )


async def _resend_pending_nwc_responses(
    ws,
    connections: list[dict[str, Any]],
) -> None:
    configured_pairs = {
        (
            str(conn.get("client_pubkey") or "").strip().lower(),
            str(conn.get("wallet_service_pubkey") or "").strip().lower(),
        )
        for conn in connections
    }
    _prune_pending_nwc_responses(time.time())

    pending_for_relay = [
        pending
        for pending in _nwc_pending_responses.values()
        if (
            str(pending.get("client_pubkey") or ""),
            str(pending.get("wallet_service_pubkey") or ""),
        ) in configured_pairs
    ]
    if pending_for_relay:
        _log(f"retrying pending responses: count={len(pending_for_relay)}")
    for pending in pending_for_relay:
        await _send_pending_nwc_response(ws, pending, retry=True)


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
    _register_pending_nwc_response(request_event, signed)
    pending = _pending_nwc_response_for_request(request_event_id)
    if pending is None:
        await ws.send(json.dumps(["EVENT", signed]))
        return
    await _send_pending_nwc_response(ws, pending, retry=False)


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


# ---------------------------------------------------------------------------
# Relay setup helpers
# ---------------------------------------------------------------------------

async def _publish_nwc_info_event(ws, conn: dict[str, Any]) -> None:
    from .app import _sign_nostr_event

    event = _build_info_event()
    signed = _sign_nostr_event(event)

    await ws.send(json.dumps(["EVENT", signed]))
    _log(
        f"info event published: conn={conn.get('name')} "
        f"event_id={_short_identifier(signed.get('id'))}"
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
    _log(
        f"subscription active: conn={conn.get('name')} sub_id={sub_id} "
        f"wallet_pubkey={_short_identifier(wallet_service_pubkey)}"
    )


async def _send_nwc_relay_subscription(
    ws,
    relay: str,
    connections: list[dict[str, Any]],
    *,
    since: int,
) -> None:
    wallet_service_pubkeys = sorted({
        str(conn.get("wallet_service_pubkey") or "").strip().lower()
        for conn in connections
        if str(conn.get("wallet_service_pubkey") or "").strip()
    })
    if not wallet_service_pubkeys:
        raise ValueError("No wallet service pubkey configured")

    client_pubkeys = sorted({
        str(conn.get("client_pubkey") or "").strip().lower()
        for conn in connections
        if str(conn.get("client_pubkey") or "").strip()
    })
    if not client_pubkeys:
        raise ValueError("No NWC client pubkey configured")

    sub_id = _build_relay_subscription_id(relay)
    await ws.send(json.dumps([
        "REQ",
        sub_id,
        {
            "kinds": [23194],
            "authors": client_pubkeys,
            "#p": wallet_service_pubkeys,
            "since": max(0, int(since)),
        },
    ]))
    _log(
        f"relay subscription active: relay={relay} sub_id={sub_id} "
        f"connections={len(connections)} clients={len(client_pubkeys)} "
        f"wallet_keys={len(wallet_service_pubkeys)}"
    )


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

async def _handle_request_event_once(
    ws,
    conn: dict[str, Any],
    event: dict[str, Any],
) -> None:
    event_id = str(event.get("id") or "")
    event_pubkey = str(event.get("pubkey") or "").strip().lower()
    tags = event.get("tags") or []
    content = str(event.get("content") or "")

    wallet_service_pubkey = _extract_first_p_tag(tags)
    if not wallet_service_pubkey:
        _log(f"request {_short_identifier(event_id)} rejected: missing p-tag")
        await _send_nwc_error(ws, event, "INVALID_REQUEST", "Missing p-tag")
        return

    matched = _find_matching_connection(event_pubkey, wallet_service_pubkey)
    if not matched:
        _log(
            f"request {_short_identifier(event_id)} rejected: "
            f"no matching connection for client={_short_identifier(event_pubkey)}"
        )
        await _send_nwc_error(ws, event, "UNAUTHORIZED", "No matching enabled connection")
        return

    server_privkey = _get_server_privkey()
    if not server_privkey:
        _log(f"request {_short_identifier(event_id)} rejected: missing server key")
        await _send_nwc_error(ws, event, "INTERNAL", "Missing server private key")
        return

    payload, parse_error = _parse_request_payload(
        event_id=event_id,
        event_pubkey=event_pubkey,
        content=content,
        server_privkey=server_privkey,
    )
    if parse_error:
        code, message = parse_error.split("::", 1)
        await _send_nwc_error(ws, event, code, message)
        return

    method = str(payload.get("method") or "").strip()
    params = payload.get("params") or {}

    param_keys = sorted(str(key) for key in params.keys()) if isinstance(params, dict) else []
    _log(
        f"request {_short_identifier(event_id)} accepted: "
        f"conn={matched.get('name')} method={method} param_keys={param_keys}"
    )

    if method == "pay_invoice":
        await _handle_pay_invoice_request(ws, event, matched, params)
        return

    if method == "make_invoice":
        await _handle_make_invoice_request(ws, event, matched, params)
        return

    if method == "lookup_invoice":
        await _handle_lookup_invoice_request(ws, event, matched, params)
        return

    if method == "get_info":
        await _handle_get_info_request(ws, event, matched)
        return

    if method == "get_balance":
        await _handle_get_balance_request(ws, event, matched)
        return

    if method == "list_transactions":
        await _handle_list_transactions_request(ws, event, matched, params)
        return

    await _send_nwc_error(ws, event, "NOT_IMPLEMENTED", f"Unsupported method: {method}")


def _prune_seen_nwc_requests(now: float) -> None:
    cutoff = now - NWC_REQUEST_DEDUP_TTL_SECONDS
    for event_id, seen_at in list(_nwc_requests_seen.items()):
        if seen_at < cutoff:
            _nwc_requests_seen.pop(event_id, None)

    overflow = len(_nwc_requests_seen) - NWC_REQUEST_DEDUP_MAX_ITEMS
    if overflow > 0:
        oldest = sorted(_nwc_requests_seen.items(), key=lambda item: item[1])
        for event_id, _ in oldest[:overflow]:
            _nwc_requests_seen.pop(event_id, None)


def _load_seen_nwc_requests() -> None:
    global _nwc_requests_seen_loaded
    if _nwc_requests_seen_loaded:
        return
    _nwc_requests_seen_loaded = True

    try:
        raw = json.loads(NWC_REQUEST_DEDUP_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return

    if not isinstance(raw, dict):
        return
    for event_id, seen_at in raw.items():
        try:
            _nwc_requests_seen[str(event_id)] = float(seen_at)
        except (TypeError, ValueError):
            continue
    _prune_seen_nwc_requests(time.time())


def _persist_seen_nwc_requests() -> None:
    try:
        NWC_REQUEST_DEDUP_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp_path = NWC_REQUEST_DEDUP_PATH.with_suffix(".tmp")
        temp_path.write_text(
            json.dumps(_nwc_requests_seen, separators=(",", ":")),
            encoding="utf-8",
        )
        temp_path.replace(NWC_REQUEST_DEDUP_PATH)
    except OSError as exc:
        _log(f"request dedup cache write failed: {_safe_log_text(exc)}")


async def _handle_request_event(
    ws,
    conn: dict[str, Any],
    event: dict[str, Any],
) -> None:
    """Execute every NIP-47 request event at most once per app runtime."""
    event_id = str(event.get("id") or "").strip()
    if not event_id:
        await _handle_request_event_once(ws, conn, event)
        return

    now = time.time()
    pending_response = None
    async with _nwc_request_lock:
        _load_seen_nwc_requests()
        _prune_seen_nwc_requests(now)
        if event_id in _nwc_requests_seen or event_id in _nwc_requests_in_flight:
            pending_response = _pending_nwc_response_for_request(event_id)
            if pending_response is None:
                _log(f"duplicate request ignored: event_id={_short_identifier(event_id)}")
                return
        else:
            _nwc_requests_in_flight.add(event_id)

    if pending_response is not None:
        _log(f"duplicate request response retry: event_id={_short_identifier(event_id)}")
        await _send_pending_nwc_response(ws, pending_response, retry=True)
        return

    try:
        await _handle_request_event_once(ws, conn, event)
    finally:
        async with _nwc_request_lock:
            _nwc_requests_in_flight.discard(event_id)
            _nwc_requests_seen[event_id] = time.time()
            _prune_seen_nwc_requests(time.time())
            _persist_seen_nwc_requests()


# ---------------------------------------------------------------------------
# Request parsing helpers
# ---------------------------------------------------------------------------

def _parse_request_payload(
    event_id: str,
    event_pubkey: str,
    content: str,
    server_privkey: str,
) -> tuple[dict[str, Any] | None, str | None]:
    from .app import _nip04_decrypt

    try:
        plaintext = _nip04_decrypt(server_privkey, event_pubkey, content)
    except Exception as exc:
        _log(
            f"request {_short_identifier(event_id)} decrypt failed: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        return None, f"DECRYPT_FAILED::{exc}"

    try:
        payload = json.loads(plaintext)
    except Exception as exc:
        _log(
            f"request {_short_identifier(event_id)} JSON invalid: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        return None, f"INVALID_REQUEST::Invalid JSON: {exc}"

    if not isinstance(payload, dict):
        return None, "INVALID_REQUEST::Invalid request payload"

    return payload, None


# ---------------------------------------------------------------------------
# Method handlers
# ---------------------------------------------------------------------------

def _extract_invoice_amount_sat(decoded: Any) -> int:
    try:
        amount_msat = getattr(decoded, "amount_msat", None)
        amount = getattr(decoded, "amount", None)

        if amount_msat is not None:
            return int(amount_msat) // 1000
        if amount is not None:
            return int(amount)
    except Exception:
        return 0

    return 0


def _build_pay_invoice_result(pay_result: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}

    if not isinstance(pay_result, dict):
        return result

    payment_preimage = pay_result.get("payment_preimage")
    payment_hash = pay_result.get("payment_hash")
    fee_sat = pay_result.get("fee_sat")

    if payment_preimage:
        result["preimage"] = str(payment_preimage)
    if payment_hash:
        result["payment_hash"] = str(payment_hash)
    if fee_sat is not None:
        result["fees_paid"] = int(fee_sat) * 1000

    return result


async def _handle_pay_invoice_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
    params: dict[str, Any],
) -> None:
    from .app import (
        _pay_bolt11_invoice,
        update_tx_history_metadata,
    )
    import bolt11

    event_id = str(event.get("id") or "")
    permissions = matched.get("permissions") or {}
    limits = matched.get("limits") or {}

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
        _log(
            f"request {_short_identifier(event_id)} invoice decode failed: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        await _send_nwc_error(ws, event, "INVALID_REQUEST", f"Invalid invoice: {exc}")
        return

    invoice_sat = _extract_invoice_amount_sat(decoded)

    if invoice_sat <= 0:
        await _send_nwc_error(ws, event, "INVALID_REQUEST", "Invoice amount missing or invalid")
        return

    if max_payment_sat > 0 and invoice_sat > max_payment_sat:
        msg = f"Invoice amount {invoice_sat} sats exceeds connection limit of {max_payment_sat} sats"
        _log(f"request {_short_identifier(event_id)} payment rejected: {msg}")
        await _send_nwc_error(ws, event, "RESTRICTED", msg)
        return

    ok, err, budget_reservation = _check_budget(matched, invoice_sat)
    if not ok:
        _log(
            f"request {_short_identifier(event_id)} payment rejected: "
            f"{_safe_log_text(err)}"
        )
        await _send_nwc_error(ws, event, "QUOTA_EXCEEDED", err)
        return

    try:
        pay_result = await _pay_bolt11_invoice(
            payment_request=invoice,
            method="nwc",
            origin="nwc",
            counterparty=str(matched.get("name") or ""),
            memo=str(params.get("description") or ""),
            amount_sat_override=invoice_sat,
        )

    except Exception as exc:
        _log(
            f"request {_short_identifier(event_id)} payment failed: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        await _send_nwc_error(ws, event, "PAYMENT_FAILED", str(exc))
        return

    result = _build_pay_invoice_result(pay_result)
    try:
        _commit_budget_usage(matched, budget_reservation)
    except Exception as exc:
        _log(
            f"request {_short_identifier(event_id)} budget update failed after "
            f"successful payment: {type(exc).__name__}: {_safe_log_text(exc)}"
        )

    _log(
        f"request {_short_identifier(event_id)} payment succeeded: "
        f"payment_hash={_short_identifier(result.get('payment_hash'))} "
        f"fees_paid_msat={result.get('fees_paid', 0)}"
    )
    await _send_nwc_success(ws, event, "pay_invoice", result)


async def _handle_make_invoice_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
    params: dict[str, Any],
) -> None:
    from .app import _create_bolt11_invoice

    event_id = str(event.get("id") or "")
    permissions = matched.get("permissions") or {}

    # No separate UI permission yet; allow receive if get_info is allowed.
    if not bool(permissions.get("get_info", True)):
        await _send_nwc_error(ws, event, "RESTRICTED", "make_invoice not allowed")
        return

    try:
        amount_msat = int(params.get("amount") or params.get("amount_msat") or 0)
    except Exception:
        amount_msat = 0

    if amount_msat <= 0:
        await _send_nwc_error(ws, event, "INVALID_REQUEST", "Missing or invalid amount")
        return

    amount_sat = max(1, (amount_msat + 999) // 1000)
    description = str(
        params.get("description")
        or params.get("memo")
        or params.get("description_hash")
        or "NWC invoice"
    ).strip()

    try:
        invoice = await _create_bolt11_invoice(
            amount_sat=amount_sat,
            memo=description,
            method="nwc",
            counterparty=str(matched.get("name") or "NWC"),
        )
    except Exception as exc:
        _log(
            f"request {_short_identifier(event_id)} invoice creation failed: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        await _send_nwc_error(ws, event, "INTERNAL", f"Failed to create invoice: {exc}")
        return

    now = int(time.time())
    expiry = int(params.get("expiry") or 3600)

    result = {
        "type": "incoming",
        "invoice": invoice["payment_request"],
        "payment_hash": invoice.get("payment_hash") or "",
        "amount": amount_sat * 1000,
        "description": description,
        "description_hash": "",
        "created_at": now,
        "expires_at": now + expiry,
        "settled_at": None,
        "settled": False,
        "fees_paid": 0,
     }

    _log(
        f"request {_short_identifier(event_id)} invoice created: "
        f"payment_hash={_short_identifier(invoice.get('payment_hash'))} "
        f"amount_msat={amount_sat * 1000} expiry={expiry}"
    )
    await _send_nwc_success(ws, event, "make_invoice", result)

async def _handle_lookup_invoice_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
    params: dict[str, Any],
) -> None:
    from .app import list_tx_history, sync_tx_history

    event_id = str(event.get("id") or "")
    await sync_tx_history()

    payment_hash = str(params.get("payment_hash") or "").strip()

    _log(
        f"request {_short_identifier(event_id)} invoice lookup: "
        f"payment_hash={_short_identifier(payment_hash)}"
    )
    if not payment_hash:
        await _send_nwc_error(ws, event, "INVALID_REQUEST", "Missing payment_hash")
        return

    tx = None

    for item in list_tx_history(500):
        if str(item.get("payment_hash") or "") == payment_hash:
            tx = item
            break

    if tx is None:
        _log(f"request {_short_identifier(event_id)} invoice lookup: not found")
        await _send_nwc_error(ws, event, "NOT_FOUND", "Invoice not found")
        return

    raw = tx.get("raw_json") or {}
    settled = tx.get("status") == "settled"

    result = {
        "type": "incoming" if tx.get("direction") == "incoming" else "outgoing",
        "invoice": raw.get("payment_request", ""),
        "payment_hash": tx.get("payment_hash", ""),
        "amount": int(tx.get("amount_sat") or 0) * 1000,
        "fees_paid": int(tx.get("fee_sat") or 0) * 1000,
        "created_at": int(tx.get("created_at") or 0),
        "expires_at": int(tx.get("created_at") or 0) + int(raw.get("expiry") or 3600),
        "settled_at": int(tx.get("settled_at") or 0) if tx.get("settled_at") else None,
        "settled": settled,
        "description": tx.get("memo") or "",
        "description_hash": raw.get("description_hash", ""),
        "preimage": raw.get("r_preimage", ""),
    }
    _log(
        f"request {_short_identifier(event_id)} invoice lookup completed: "
        f"status={tx.get('status')} method={tx.get('method')} direction={tx.get('direction')}"
    )
    await _send_nwc_success(ws, event, "lookup_invoice", result)

async def _handle_get_info_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
) -> None:
    permissions = matched.get("permissions") or {}

    if not bool(permissions.get("get_info", False)):
        await _send_nwc_error(ws, event, "RESTRICTED", "get_info not allowed")
        return

    result = {
        "alias": "BOLT12 Pay",
        "network": "mainnet",
        "block_height": 0,
        "methods": [
            "pay_invoice",
            "make_invoice",
            "lookup_invoice",
            "list_transactions",
            "get_info",
            "get_balance",
         ],
    }
    await _send_nwc_success(ws, event, "get_info", result)


def _get_virtual_nwc_balance_msat(conn: dict[str, Any]) -> int:
    limits = conn.get("limits") or {}
    usage = conn.get("usage") or {}

    budget_period = str(limits.get("budget_period") or "none").strip().lower()
    budget_amount_sat = int(limits.get("budget_amount_sat") or 0)
    max_payment_sat = int(limits.get("max_payment_sat") or 0)

    if budget_period != "none" and budget_amount_sat > 0:
        current_period_key = _current_budget_period_key(budget_period)
        stored_period_key = str(usage.get("period_key") or "")
        spent_sat = int(usage.get("spent_sat") or 0)

        if stored_period_key != current_period_key:
            spent_sat = 0

        remaining_sat = max(budget_amount_sat - spent_sat, 0)
        return remaining_sat * 1000

    if max_payment_sat > 0:
        return max_payment_sat * 1000

    return 0


async def _handle_get_balance_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
) -> None:
    permissions = matched.get("permissions") or {}

    if not bool(permissions.get("get_balance", False)):
        await _send_nwc_error(ws, event, "RESTRICTED", "get_balance not allowed")
        return

    result = {
        "balance": _get_virtual_nwc_balance_msat(matched),
    }
    await _send_nwc_success(ws, event, "get_balance", result)

async def _handle_list_transactions_request(
    ws,
    event: dict[str, Any],
    matched: dict[str, Any],
    params: dict[str, Any],
) -> None:
    from .app import list_tx_history

    permissions = matched.get("permissions") or {}

    if not bool(permissions.get("get_balance", False)):
        await _send_nwc_error(ws, event, "RESTRICTED", "list_transactions not allowed")
        return

    limit = int(params.get("limit") or 50)
    history = list_tx_history(limit)

    transactions = []

    for item in history:
        transactions.append({
            "type": "incoming" if item["direction"] == "incoming" else "outgoing",
            "invoice": item.get("raw_json", {}).get("payment_request", ""),
            "payment_hash": item.get("payment_hash", ""),
            "amount": int(item.get("amount_sat") or 0) * 1000,
            "fees_paid": int(item.get("fee_sat") or 0) * 1000,
            "created_at": int(item.get("created_at") or 0),
            "settled_at": int(item.get("settled_at") or 0) if item.get("settled_at") else None,
            "description": item.get("memo") or "",
        })

    await _send_nwc_success(
        ws,
        event,
        "list_transactions",
        {"transactions": transactions},
    )

# ---------------------------------------------------------------------------
# Relay message handling
# ---------------------------------------------------------------------------

async def _handle_event_message(ws, conn: dict[str, Any], data: list[Any]) -> None:
    if len(data) < 3 or not isinstance(data[2], dict):
        _log(f"malformed EVENT on {conn.get('name')} ignored: items={len(data)}")
        return

    sub_id = str(data[1] or "")
    event = data[2]

    event_id = str(event.get("id") or "")
    pubkey = str(event.get("pubkey") or "").strip().lower()
    kind = event.get("kind")
    _log(
        f"EVENT on {conn.get('name')}: sub_id={sub_id} kind={kind} "
        f"event_id={_short_identifier(event_id)} pubkey={_short_identifier(pubkey)}"
    )

    expected_client_pubkey = str(conn.get("client_pubkey") or "").strip().lower()
    if pubkey != expected_client_pubkey:
        _log(
            f"EVENT on {conn.get('name')} ignored: "
            f"client={_short_identifier(pubkey)} "
            f"expected={_short_identifier(expected_client_pubkey)}"
        )
        return

    _log(f"EVENT on {conn.get('name')} accepted: event_id={_short_identifier(event_id)}")

    await _handle_request_event(ws, conn, event)


def _handle_eose_message(conn: dict[str, Any], data: list[Any]) -> None:
    sub_id = str(data[1] or "-") if len(data) > 1 else "-"
    _log(f"EOSE on {conn.get('name')}: sub_id={sub_id}")


def _handle_notice_message(conn: dict[str, Any], data: list[Any]) -> None:
    notice = data[1] if len(data) > 1 else ""
    _log(f"NOTICE on {conn.get('name')}: {_safe_log_text(notice)}")


def _handle_ok_message(conn: dict[str, Any], data: list[Any]) -> None:
    event_id = str(data[1] if len(data) > 1 else "").strip()
    accepted = data[2] if len(data) > 2 else None
    message = data[3] if len(data) > 3 else ""
    _log(
        f"OK on {conn.get('name')}: event_id={_short_identifier(event_id)} "
        f"accepted={accepted} message={_safe_log_text(message)}"
    )

    pending = _nwc_pending_responses.get(event_id)
    if pending is None:
        return

    message_prefix = str(message or "").strip().lower().split(":", 1)[0]
    if accepted is True or message_prefix == "duplicate":
        _remove_pending_nwc_response(event_id)
        return

    if message_prefix in NWC_RETRYABLE_RELAY_REJECTION_PREFIXES:
        raise NwcRelayPublishRejected(
            f"response {_short_identifier(event_id)} rejected: {_safe_log_text(message)}"
        )

    _remove_pending_nwc_response(event_id)
    _log(
        f"response permanently rejected: event_id={_short_identifier(event_id)} "
        f"message={_safe_log_text(message)}"
    )


def _handle_closed_message(
    conn: dict[str, Any],
    data: list[Any],
    *,
    expected_sub_id: str,
) -> None:
    sub_id = str(data[1] if len(data) > 1 else "").strip()
    message = data[2] if len(data) > 2 else ""
    _log(
        f"CLOSED on {conn.get('name')}: sub_id={sub_id or '-'} "
        f"message={_safe_log_text(message)}"
    )
    if sub_id != expected_sub_id:
        return
    raise NwcRelaySubscriptionClosed(
        f"subscription {sub_id} closed: {_safe_log_text(message)}"
    )


def _handle_unhandled_message(conn: dict[str, Any], data: list[Any]) -> None:
    msg_type = str(data[0]) if data else "unknown"
    _log(f"unhandled relay message on {conn.get('name')}: type={_safe_log_text(msg_type)}")


async def handle_nwc_message(ws, conn: dict[str, Any], msg: str) -> None:
    try:
        data = json.loads(msg)
    except Exception:
        _log(f"non-JSON message on {conn.get('name')}: {_safe_log_text(msg, limit=120)}")
        return

    if not isinstance(data, list) or not data:
        _log(
            f"unexpected message format on {conn.get('name')}: "
            f"type={type(data).__name__}"
        )
        return

    msg_type = str(data[0])

    if msg_type == "EVENT":
        await _handle_event_message(ws, conn, data)
        return

    if msg_type == "EOSE":
        _handle_eose_message(conn, data)
        return

    if msg_type == "NOTICE":
        _handle_notice_message(conn, data)
        return

    if msg_type == "OK":
        _handle_ok_message(conn, data)
        return

    if msg_type == "CLOSED":
        _handle_closed_message(
            conn,
            data,
            expected_sub_id=_build_subscription_id(conn),
        )
        return

    _handle_unhandled_message(conn, data)


def _connection_for_relay_event(
    connections: list[dict[str, Any]],
    event: dict[str, Any],
) -> dict[str, Any] | None:
    event_pubkey = str(event.get("pubkey") or "").strip().lower()
    wallet_service_pubkey = _extract_first_p_tag(event.get("tags") or [])

    for conn in connections:
        if (
            str(conn.get("client_pubkey") or "").strip().lower()
            != event_pubkey
        ):
            continue
        if (
            str(conn.get("wallet_service_pubkey") or "").strip().lower()
            == wallet_service_pubkey
        ):
            return conn

    return None


async def handle_nwc_relay_message(
    ws,
    relay: str,
    connections: list[dict[str, Any]],
    msg: str,
) -> int | None:
    try:
        data = json.loads(msg)
    except Exception:
        _log(f"non-JSON message on {relay}: {_safe_log_text(msg, limit=120)}")
        return None

    if not isinstance(data, list) or not data:
        _log(f"unexpected message format on {relay}: type={type(data).__name__}")
        return None

    msg_type = str(data[0])
    if msg_type == "EVENT":
        if len(data) < 3 or not isinstance(data[2], dict):
            _log(f"malformed EVENT on {relay} ignored: items={len(data)}")
            return None

        event = data[2]
        matched = _connection_for_relay_event(connections, event)
        if matched is None:
            _log(
                f"EVENT on {relay} ignored: no configured client match "
                f"event_id={_short_identifier(event.get('id'))} "
                f"client={_short_identifier(event.get('pubkey'))}"
            )
            return None

        _log(
            f"EVENT on {relay} accepted: conn={matched.get('name')} "
            f"event_id={_short_identifier(event.get('id'))}"
        )
        await _handle_request_event(ws, matched, event)
        try:
            return int(event.get("created_at") or 0) or None
        except (TypeError, ValueError):
            return None

    label = {
        "name": f"relay {relay}",
    }
    if msg_type == "EOSE":
        _handle_eose_message(label, data)
        return None
    if msg_type == "NOTICE":
        _handle_notice_message(label, data)
        return None
    if msg_type == "OK":
        _handle_ok_message(label, data)
        return None
    if msg_type == "CLOSED":
        _handle_closed_message(
            label,
            data,
            expected_sub_id=_build_relay_subscription_id(relay),
        )
        return None
    _handle_unhandled_message(label, data)
    return None


def _retry_after_seconds(exc: Exception) -> float | None:
    headers = getattr(exc, "headers", None)
    if headers is None:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
    if headers is None:
        return None

    try:
        raw_value = headers.get("Retry-After")
        if raw_value is None:
            raw_value = headers.get("retry-after")
        value = float(raw_value)
    except (AttributeError, TypeError, ValueError):
        return None
    return max(0.0, value)


def _nwc_reconnect_delay(
    failure_count: int,
    exc: Exception,
    *,
    jitter: float | None = None,
) -> float:
    exponent = max(0, min(int(failure_count) - 1, 16))
    delay = min(
        NWC_RECONNECT_BASE_SECONDS * (2 ** exponent),
        NWC_RECONNECT_MAX_SECONDS,
    )
    retry_after = _retry_after_seconds(exc)
    if retry_after is not None:
        delay = max(delay, min(retry_after, NWC_RECONNECT_MAX_SECONDS))

    jitter_value = random.uniform(0.85, 1.15) if jitter is None else jitter
    return min(delay * max(0.0, jitter_value), NWC_RECONNECT_MAX_SECONDS)




# ---------------------------------------------------------------------------
# Connection loop
# ---------------------------------------------------------------------------

async def nwc_connection_loop(conn: dict[str, Any]) -> None:
    relay = str(conn.get("relay_url") or "").strip()
    if not relay:
        name = str(conn.get("name") or "NWC Connection").strip()
        _log(f"skipping {name}: no relay URL configured")
        return

    await nwc_relay_loop(relay, [conn])


async def nwc_relay_loop(
    relay: str,
    connections: list[dict[str, Any]],
) -> None:
    names = ", ".join(
        str(conn.get("name") or "NWC Connection").strip()
        for conn in connections
    )
    failure_count = 0
    subscription_since = int(time.time()) - NWC_INITIAL_LOOKBACK_SECONDS
    info_event_published_at: float | None = None

    while True:
        connected_at: float | None = None
        try:
            _log(
                f"connecting relay: {relay} "
                f"connections={len(connections)} names={names}"
            )
            async with websockets.connect(relay, ping_interval=20, ping_timeout=20) as ws:
                connected_at = time.monotonic()
                _log(
                    f"connected relay: {relay} connections={len(connections)}"
                )

                await _resend_pending_nwc_responses(ws, connections)
                if (
                    info_event_published_at is None
                    or time.monotonic() - info_event_published_at
                    >= NWC_INFO_REPUBLISH_SECONDS
                ):
                    await _publish_nwc_info_event(ws, connections[0])
                    info_event_published_at = time.monotonic()
                await _send_nwc_relay_subscription(
                    ws,
                    relay,
                    connections,
                    since=subscription_since,
                )

                while True:
                    msg = await ws.recv()
                    event_created_at = await handle_nwc_relay_message(
                        ws,
                        relay,
                        connections,
                        msg,
                    )
                    if event_created_at:
                        subscription_since = max(
                            subscription_since,
                            event_created_at - 5,
                        )

        except Exception as exc:
            if (
                connected_at is not None
                and time.monotonic() - connected_at >= NWC_STABLE_CONNECTION_SECONDS
            ):
                failure_count = 0
            failure_count += 1
            retry_delay = _nwc_reconnect_delay(failure_count, exc)
            _log(
                f"relay reconnect scheduled: {relay} "
                f"connections={len(connections)} failures={failure_count} "
                f"retry_in={retry_delay:.1f}s after "
                f"{type(exc).__name__}: {_safe_log_text(exc)}"
            )
            await asyncio.sleep(retry_delay)


# ---------------------------------------------------------------------------
# Runtime lifecycle
# ---------------------------------------------------------------------------

def _get_enabled_connections() -> list[dict[str, Any]]:
    try:
        connections = load_connections()
    except Exception as exc:
        _log(
            f"failed to load connections: "
            f"{type(exc).__name__}: {_safe_log_text(exc)}"
        )
        return []

    _log(f"loaded connections: {len(connections)}")

    enabled = [c for c in connections if bool(c.get("enabled", True))]
    _log(f"enabled connections: {len(enabled)}")
    return enabled


def _log_scheduled_connection(conn: dict[str, Any]) -> None:
    _log(
        f"scheduling connection: name={conn.get('name')} "
        f"relay={conn.get('relay_url')} "
        f"client_pubkey={_short_identifier(conn.get('client_pubkey'))}"
    )


async def _cancel_nwc_task(task: asyncio.Task) -> None:
    if not task.done():
        task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


async def _stop_all_nwc_tasks() -> None:
    global _nwc_tasks

    for task in list(_nwc_tasks.values()):
        await _cancel_nwc_task(task)

    _nwc_tasks = {}


async def _start_nwc_tasks() -> None:
    global _nwc_tasks

    if not _get_server_privkey():
        _log("server key locked, relay connections waiting for unlock")
        return

    enabled = _get_enabled_connections()
    if not enabled:
        _log("no enabled connections, runtime idle")
        return

    connections_by_relay: dict[str, list[dict[str, Any]]] = {}
    for conn in enabled:
        relay = str(conn.get("relay_url") or "").strip()
        if not relay:
            _log(f"skipping {conn.get('name')}: no relay URL configured")
            continue
        _log_scheduled_connection(conn)
        connections_by_relay.setdefault(relay, []).append(conn)

    for relay, relay_connections in connections_by_relay.items():
        _log(
            f"scheduling shared relay connection: relay={relay} "
            f"logical_connections={len(relay_connections)}"
        )
        _nwc_tasks[relay] = asyncio.create_task(
            nwc_relay_loop(relay, relay_connections)
        )


async def _restart_nwc_tasks() -> None:
    await _stop_all_nwc_tasks()
    await _start_nwc_tasks()


async def reload_nwc_runtime() -> None:
    async with _nwc_runtime_lock:
        _log("reload requested")
        await _restart_nwc_tasks()
        _log("reload complete")


async def start_nwc_runtime() -> None:
    _log("runtime starting (clean)...")
    async with _nwc_runtime_lock:
        await _restart_nwc_tasks()
