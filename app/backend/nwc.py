from __future__ import annotations

import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

from coincurve import PrivateKey

NWC_CONNECTIONS_PATH = Path("/data/config/nwc_connections.json")
DEFAULT_NWC_RELAY = "wss://relay.getalby.com/v1"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _derive_nostr_pubkey_from_privkey_hex(privkey_hex: str) -> str:
    raw = bytes.fromhex(privkey_hex)
    pub_uncompressed = PrivateKey(raw).public_key.format(compressed=False)
    return pub_uncompressed[1:33].hex()


def _load_raw() -> list[dict[str, Any]]:
    try:
        data = json.loads(NWC_CONNECTIONS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception:
        return []


def _save_raw(items: list[dict[str, Any]]) -> None:
    _ensure_parent(NWC_CONNECTIONS_PATH)
    NWC_CONNECTIONS_PATH.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _find_connection_index(items: list[dict[str, Any]], connection_id: str) -> int:
    for index, item in enumerate(items):
        if item.get("id") == connection_id:
            return index
    return -1


def list_nwc_connections() -> list[dict[str, Any]]:
    items = _load_raw()
    cleaned: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cleaned.append(item)
    return cleaned


def get_nwc_connection(connection_id: str) -> dict[str, Any] | None:
    items = list_nwc_connections()
    index = _find_connection_index(items, connection_id)
    return items[index] if index >= 0 else None


def create_nwc_connection(
    *,
    wallet_service_pubkey: str,
    name: str,
    relay_url: str,
    allow_get_info: bool,
    allow_get_balance: bool,
    allow_pay_invoice: bool,
    max_payment_sat: int,
    budget_period: str,
    budget_amount_sat: int,
) -> dict[str, Any]:
    now = int(time.time())
    client_secret = secrets.token_hex(32)
    client_pubkey = _derive_nostr_pubkey_from_privkey_hex(client_secret)

    item = {
        "id": str(uuid.uuid4()),
        "name": name.strip() or "NWC Connection",
        "relay_url": (relay_url or DEFAULT_NWC_RELAY).strip(),
        "wallet_service_pubkey": wallet_service_pubkey.strip().lower(),
        "client_secret": client_secret,
        "client_pubkey": client_pubkey,
        "permissions": {
            "get_info": bool(allow_get_info),
            "get_balance": bool(allow_get_balance),
            "pay_invoice": bool(allow_pay_invoice),
        },
        "limits": {
            "max_payment_sat": int(max_payment_sat),
            "budget_period": str(budget_period or "none").strip().lower(),
            "budget_amount_sat": int(budget_amount_sat or 0),
        },
        "enabled": True,
        "created_at": now,
    }

    items = list_nwc_connections()
    items.append(item)
    _save_raw(items)
    return item


def build_nwc_uri(item: dict[str, Any]) -> str:
    from urllib.parse import quote

    wallet_service_pubkey = str(item.get("wallet_service_pubkey") or "").strip()
    relay_url = str(item.get("relay_url") or "").strip()
    client_secret = str(item.get("client_secret") or "").strip()

    if not wallet_service_pubkey or not relay_url or not client_secret:
        raise ValueError("Incomplete NWC connection")

    return (
        f"nostr+walletconnect://{wallet_service_pubkey}"
        f"?relay={quote(relay_url, safe='')}"
        f"&secret={client_secret}"
    )


def toggle_nwc_connection(connection_id: str) -> dict[str, Any]:
    items = list_nwc_connections()
    index = _find_connection_index(items, connection_id)

    if index < 0:
        raise KeyError("NWC connection not found")

    item = items[index]
    item["enabled"] = not bool(item.get("enabled", True))

    _save_raw(items)
    return item


def delete_nwc_connection(connection_id: str) -> None:
    items = list_nwc_connections()
    index = _find_connection_index(items, connection_id)

    if index < 0:
        raise KeyError("NWC connection not found")

    del items[index]
    _save_raw(items)


def update_nwc_connection_usage(connection_id: str, period_key: str, spent_sat: int) -> dict[str, Any]:
    items = list_nwc_connections()
    index = _find_connection_index(items, connection_id)

    if index < 0:
        raise KeyError("NWC connection not found")

    item = items[index]
    item["usage"] = {
        "period_key": str(period_key),
        "spent_sat": int(spent_sat),
    }

    _save_raw(items)
    return item


def load_connections() -> list[dict[str, Any]]:
    return list_nwc_connections()
