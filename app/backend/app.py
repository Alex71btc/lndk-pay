from __future__ import annotations

import json
import math
import os
import re
import shlex
import subprocess
import secrets
import time
import hmac
import struct
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse, quote

import dns.exception
import dns.resolver
import httpx
import qrcode
import hashlib
import base64
import bech32
from io import BytesIO
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.responses import FileResponse, Response, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request as StarletteRequest
from pydantic import BaseModel, Field
from backend.config import load_config, save_config
from backend.nwc import (
    list_nwc_connections,
    create_nwc_connection,
    get_nwc_connection,
    build_nwc_uri,
    toggle_nwc_connection,
    delete_nwc_connection,
)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from coincurve import PrivateKey, PublicKey

# --- Configuration ---------------------------------------------------------
HOME_URL = "/"
APP_URL = "/app"
PAY_URL = "/pay"
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
PUBLIC_DIR = PROJECT_ROOT / "frontend" / "public"
ADMIN_DIR = PROJECT_ROOT / "frontend" / "admin"

LNDK_CLI = os.environ.get("LNDK_CLI", "lndk-cli")
LNDK_NETWORK = os.environ.get("LNDK_NETWORK", "bitcoin")
LNDK_GRPC_HOST = os.environ.get("LNDK_GRPC_HOST", "").strip()
LNDK_GRPC_PORT = os.environ.get("LNDK_GRPC_PORT", "7000").strip()
LNDK_CERT_PATH = os.environ.get("LNDK_CERT_PATH", str(Path.home() / "lndk-tls-cert.pem"))
LNDK_MACAROON_PATH = os.environ.get("LNDK_MACAROON_PATH", str(Path.home() / "admin.macaroon"))
REQUEST_TIMEOUT = float(os.environ.get("LNDK_TIMEOUT_SECONDS", "30"))
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
ALLOW_PAY_OFFER = os.environ.get("ALLOW_PAY_OFFER", "false").lower() in {"1", "true", "yes", "on"}

PUBLIC_BIP353_ADDRESS = os.environ.get("PUBLIC_BIP353_ADDRESS", "").strip()
PUBLIC_LNURL_ADDRESS = os.environ.get("PUBLIC_LNURL_ADDRESS", "").strip()
LNURL_BASE_DOMAIN = os.environ.get("LNURL_BASE_DOMAIN", "").strip().lower()
LNURL_BASE_URL = os.environ.get("LNURL_BASE_URL", "").strip().rstrip("/")
LND_REST_URL = os.environ.get("LND_REST_URL", "").strip().rstrip("/")
LND_REST_INSECURE = os.environ.get("LND_REST_INSECURE", "false").lower() in {"1", "true", "yes", "on"}
PAY_UI_PASSWORD = os.getenv("PAY_UI_PASSWORD", "").strip()
PAY_UI_SESSION_TTL = int(os.getenv("PAY_UI_SESSION_TTL", "1800"))
PAY_UI_COOKIE_NAME = "pay_session"
PAY_SESSIONS: dict[str, dict] = {}

NWC_SESSION_TTL = int(os.getenv("NWC_SESSION_TTL", "180"))
NWC_COOKIE_NAME = "nwc_session"
NWC_SESSIONS: dict[str, dict] = {}


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _get_ui_password_hash() -> str:
    cfg = load_config()
    return str(cfg.get("ui_password_hash", "")).strip()


def _is_pay_ui_enabled() -> bool:
    return bool(_get_ui_password_hash() or PAY_UI_PASSWORD)


def _is_pay_ui_configured() -> bool:
    return bool(_get_ui_password_hash() or PAY_UI_PASSWORD)


def _verify_ui_password(password: str) -> bool:
    stored_hash = _get_ui_password_hash()

    if stored_hash:
        return hmac.compare_digest(_hash_password(password or ""), stored_hash)

    if PAY_UI_PASSWORD:
        return hmac.compare_digest(password or "", PAY_UI_PASSWORD)

    return False


def get_public_bolt12_address():
    cfg = load_config()
    return (cfg.get("public_bolt12_address") or "").strip() or PUBLIC_BIP353_ADDRESS

def get_public_lnurl_address():
    cfg = load_config()
    return (cfg.get("public_lnurl_address") or "").strip() or PUBLIC_LNURL_ADDRESS



def _mask_secret(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= 12:
        return "*" * len(value)
    return value[:4] + "…" + value[-4:]


def _hex_pubkey_to_npub(pubkey_hex: str) -> str:
    try:
        data = bytes.fromhex(pubkey_hex)
        five = bech32.convertbits(data, 8, 5, True)
        if not five:
            return ""
        return bech32.bech32_encode("npub", five)
    except Exception:
        return ""


def _derive_pubkey_from_privkey_hex(privkey_hex: str) -> str:
    privkey_hex = (privkey_hex or "").strip().lower()
    if not privkey_hex:
        return ""
    try:
        priv = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
        return priv.public_key_xonly.format().hex()
    except Exception:
        return ""


def _normalize_nsec_to_hex(nsec: str) -> str:
    nsec = (nsec or "").strip()
    if not nsec:
        return ""
    if len(nsec) == 64:
        return nsec.lower()
    hrp, data = bech32.bech32_decode(nsec)
    if hrp != "nsec" or data is None:
        raise ValueError("Invalid nsec")
    decoded = bech32.convertbits(data, 5, 8, False)
    if not decoded:
        raise ValueError("Invalid nsec payload")
    return bytes(decoded).hex()


def _generate_nostr_private_key_hex() -> str:
    return secrets.token_hex(32)


def _get_nostr_admin_status() -> dict[str, Any]:
    cfg = load_config()

    server_privkey = str(
        cfg.get("nostr_server_privkey")
        or _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()

    notify_nsec = str(
        cfg.get("nostr_notify_nsec")
        or _get_secret("NOSTR_NOTIFY_NSEC", "nostr_notify_nsec", default="")
        or ""
    ).strip()

    server_pubkey_hex = _derive_pubkey_from_privkey_hex(server_privkey) if server_privkey else ""
    notify_pubkey_hex = ""

    try:
        notify_hex = _normalize_nsec_to_hex(notify_nsec) if notify_nsec else ""
        notify_pubkey_hex = _derive_pubkey_from_privkey_hex(notify_hex) if notify_hex else ""
    except Exception:
        notify_pubkey_hex = ""

    return {
        "server_key_configured": bool(server_privkey),
        "server_pubkey_hex": server_pubkey_hex,
        "server_npub": _hex_pubkey_to_npub(server_pubkey_hex) if server_pubkey_hex else "",
        "notify_key_configured": bool(notify_nsec),
        "notify_pubkey_hex": notify_pubkey_hex,
        "notify_npub": _hex_pubkey_to_npub(notify_pubkey_hex) if notify_pubkey_hex else "",
        "notify_nsec_masked": _mask_secret(notify_nsec),
    }

def get_cloudflare_config():
    cfg = load_config()
    cf = cfg.get("cloudflare", {}) or {}
    dns_mode = str(cfg.get("dns_mode", "")).strip().lower()

    return {
        "enabled": bool(cf.get("enabled")) or dns_mode == "cloudflare",
        "zone_name": str(cf.get("zone_name", "")).strip(),
        "zone_id": str(cf.get("zone_id", "")).strip(),
        "api_token": str(cf.get("api_token", "")).strip(),
    }

DNS_RESOLVER_LIFETIME = float(os.environ.get("DNS_RESOLVER_LIFETIME", "10"))
DNS_RESOLVER_TIMEOUT = float(os.environ.get("DNS_RESOLVER_TIMEOUT", "10"))

LNURL_MIN_SENDABLE_MSAT = int(os.environ.get("LNURL_MIN_SENDABLE_MSAT", "1000"))
LNURL_MAX_SENDABLE_MSAT = int(os.environ.get("LNURL_MAX_SENDABLE_MSAT", "1000000000"))
LNURL_COMMENT_ALLOWED = int(os.environ.get("LNURL_COMMENT_ALLOWED", "120"))
LNURL_ALIAS_MODE = os.environ.get("LNURL_ALIAS_MODE", "shared").strip().lower()
LNURL_SHARED_DESCRIPTION = os.environ.get("LNURL_SHARED_DESCRIPTION", "LNURL payment").strip()
LNURL_DEFAULT_DESCRIPTION = os.environ.get("LNURL_DEFAULT_DESCRIPTION", "Lightning payment").strip()
LNURL_ALIAS_MAP_RAW = os.environ.get("LNURL_ALIAS_MAP", "").strip()
LND_TLS_CERT_PATH = os.environ.get("LND_TLS_CERT_PATH", "/secrets/tls.cert").strip()
LND_MACAROON_PATH = os.environ.get("LND_MACAROON_PATH", "/secrets/admin.macaroon").strip()
LND_REST_TIMEOUT = float(os.environ.get("LND_REST_TIMEOUT_SECONDS", "30"))
# --- Nostr / Zap Config ----------------------------------------------

# === CONFIG SYSTEM (file + env fallback) ===
APP_DATA_DIR = Path(os.getenv("APP_DATA_DIR", "/data"))
CONFIG_DIR = APP_DATA_DIR / "config"
CONFIG_JSON_PATH = Path(os.getenv("CONFIG_JSON_PATH", str(APP_DATA_DIR / "config.json")))
SECRETS_JSON_PATH = Path(os.getenv("SECRETS_JSON_PATH", str(CONFIG_DIR / "secrets.json")))


def _load_json_file(path: Path):
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _deep_get(data, *keys, default=None):
    cur = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _get_setting(env_name, *config_path, default=None):
    env_val = os.getenv(env_name)
    if env_val not in (None, ""):
        return env_val
    return _deep_get(_load_json_file(CONFIG_JSON_PATH), *config_path, default=default)


def _get_secret(env_name, *config_path, default=None):
    env_val = os.getenv(env_name)
    if env_val not in (None, ""):
        return env_val
    return _deep_get(_load_json_file(SECRETS_JSON_PATH), *config_path, default=default)

NOSTR_SERVER_PRIVKEY = _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="").strip().lower()
NOSTR_NOTIFY_NSEC = _get_secret("NOSTR_NOTIFY_NSEC", "nostr_notify_nsec", default="").strip()
_NOSTR_DEFAULT_RELAYS_RAW = _get_setting(
    "NOSTR_DEFAULT_RELAYS",
    "nostr",
    "default_relays",
    default=[
        "wss://relay.primal.net",
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.getalby.com/v1",
        "wss://offchain.pub",
        "wss://relay.alex71btc.com",
    ],
)

if isinstance(_NOSTR_DEFAULT_RELAYS_RAW, str):
    NOSTR_DEFAULT_RELAYS = [x.strip() for x in _NOSTR_DEFAULT_RELAYS_RAW.split(",") if x.strip()]
else:
    NOSTR_DEFAULT_RELAYS = [str(x).strip() for x in (_NOSTR_DEFAULT_RELAYS_RAW or []) if str(x).strip()]


OLD_DEFAULT_NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
]

TARGET_DEFAULT_NOSTR_RELAYS = [
    "wss://relay.primal.net",
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.getalby.com/v1",
    "wss://offchain.pub",
    "wss://relay.alex71btc.com",
]


def _local_normalize_relays(relays):
    out = []
    seen = set()
    for relay in relays or []:
        parts = str(relay).replace("\r", "").split("\n")
        for part in parts:
            value = part.strip()
            if not value:
                continue
            if not value.startswith("wss://"):
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
    return out


def _effective_default_nostr_relays():
    current = _local_normalize_relays(NOSTR_DEFAULT_RELAYS)
    old = _local_normalize_relays(OLD_DEFAULT_NOSTR_RELAYS)
    target = _local_normalize_relays(TARGET_DEFAULT_NOSTR_RELAYS)

    if not current or current == old:
        return target
    return current


def _migrate_default_nostr_relays() -> None:
    try:
        def _local_normalize_relays(relays):
            out = []
            seen = set()
            for relay in relays or []:
                parts = str(relay).replace("\r", "").split("\n")
                for part in parts:
                    value = part.strip()
                    if not value:
                        continue
                    if not value.startswith("wss://"):
                        continue
                    if value in seen:
                        continue
                    seen.add(value)
                    out.append(value)
            return out

        cfg = _load_json_file(CONFIG_JSON_PATH)
        if not isinstance(cfg, dict):
            cfg = {}

        nostr_cfg = cfg.get("nostr") or {}
        if not isinstance(nostr_cfg, dict):
            nostr_cfg = {}

        current = nostr_cfg.get("default_relays")

        normalized_current = _local_normalize_relays(current or [])
        normalized_old = _local_normalize_relays(OLD_DEFAULT_NOSTR_RELAYS)
        normalized_target = _local_normalize_relays(TARGET_DEFAULT_NOSTR_RELAYS)

        if not normalized_current or normalized_current == normalized_old:
            cfg.setdefault("nostr", {})
            cfg["nostr"]["default_relays"] = normalized_target
            CONFIG_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_JSON_PATH.write_text(
                json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8"
            )
    except Exception:
        pass


_migrate_default_nostr_relays()


NOSTR_ZAP_POLL_INTERVAL = int(_get_setting("NOSTR_ZAP_POLL_INTERVAL", "nostr", "zap_poll_interval", default=15) or 15)

# Extract the lno... offer string from lndk-cli output like:
# Offer: CreateOfferResponse { offer: "lno1..." }.
OFFER_RE = re.compile(
    r'offer:\s*CreateOfferResponse\s*\{\s*offer:\s*"(?P<offer>lno[^"\s]+)"',
    re.IGNORECASE,
)

HRN_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LNURL_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


# --- Models ----------------------------------------------------------------


class NwcUnlockRequest(BaseModel):
    password: str = Field(default="")

class OfferRequest(BaseModel):
    amount: Optional[int] = Field(
        default=None,
        ge=1,
        description="Minimum amount in sats. If omitted, backend uses 1 sat.",
    )
    description: str = Field(default="bolt12@example.com", min_length=1, max_length=200)
    issuer: Optional[str] = Field(default=None, max_length=120)
    expiry: Optional[int] = Field(default=None, ge=1)
    quantity: Optional[int] = Field(default=None, ge=0)


class OfferResponse(BaseModel):
    offer: str
    raw_output: str


class DecodeRequest(BaseModel):
    offer: str = Field(min_length=4)


class DecodeResponse(BaseModel):
    raw_output: str

class PayBolt11Request(BaseModel):
    invoice: str = Field(
        min_length=10,
        description="BOLT11 invoice like lnbc...",
    )

class PayOfferRequest(BaseModel):
    offer: str = Field(
        min_length=4,
        description="Either an lno... offer or a BIP353 human-readable address",
    )
    amount_sat: int = Field(ge=1, description="Amount to pay in sats")
    payer_note: Optional[str] = Field(default=None, max_length=300)

class PayAddressRequest(BaseModel):
    target: str = Field(
        min_length=3,
        description="Lightning Address or BIP353 human-readable address",
    )
    amount_sat: int = Field(ge=1, description="Amount to pay in sats")
    payer_note: Optional[str] = Field(default=None, max_length=300)

class PayOfferResponse(BaseModel):
    resolved_offer: str
    raw_output: str


class HealthResponse(BaseModel):
    ok: bool
    cli: str
    grpc_host: str
    grpc_port: str
    cert_path: str
    macaroon_path: str
    allow_pay_offer: bool


class PublicInfoResponse(BaseModel):
    address: str
    fallback_address: str
    offer: str


class LnurlInfoResponse(BaseModel):
    lightning_address: str
    lnurl: str
    lnurlp_url: str


class LnurlPayMetadataResponse(BaseModel):
    callback: str
    minSendable: int
    maxSendable: int
    metadata: str
    tag: str = "payRequest"
    commentAllowed: int = 0
    allowsNostr: bool = True
    nostrPubkey: str = ""


class CloudflareBIP353Request(BaseModel):
    record_name: str
    offer: str

class AliasCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="Lightning payment", min_length=1, max_length=200)
    amount_sat: Optional[int] = Field(default=None, ge=1)
    publish_dns: bool = Field(default=False)


class AliasResponse(BaseModel):
    name: str
    address: str
    description: str
    amount_sat: Optional[int] = None
    dns_name: Optional[str] = None
    dns_content: Optional[str] = None
    published: bool = False
    last_offer: Optional[str] = None
class CreateInvoiceRequest(BaseModel):
    amount_sat: int = Field(ge=1)
    memo: str = Field(default="bolt12-pay", max_length=200)
    expiry: Optional[int] = Field(default=3600, ge=1)


class CreateInvoiceResponse(BaseModel):
    payment_request: str
    payment_hash: str
    expires_at: Optional[str] = None

class AliasUpdateRequest(BaseModel):
    description: str = Field(min_length=1, max_length=200)
    amount_sat: Optional[int] = Field(default=None, ge=1)

class PayLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=300)
    totp_code: Optional[str] = Field(default="")

from typing import Literal

class NwcConnectionCreateRequest(BaseModel):
    name: str = "NWC Connection"
    relay_url: str = "wss://relay.getalby.com/v1"
    allow_get_info: bool = True
    allow_get_balance: bool = True
    allow_pay_invoice: bool = True
    max_payment_sat: int = Field(default=100000, ge=1, le=100000000)
    budget_period: Literal["none", "day", "week", "month"] = "none"
    budget_amount_sat: int = Field(default=0, ge=0, le=1000000000)



# --- App -------------------------------------------------------------------


# -------------------------------
# NOSTR NIP-05 Mapping
# -------------------------------


def _get_nostr_pubkey_for_name(name: str) -> str:
    if not name:
        return ""
    return NOSTR_NAME_MAP.get(name.strip().lower(), "")




def _npub_to_hex_pubkey(npub: str) -> str:
    npub = (npub or "").strip().lower()
    if not npub:
        return ""

    hrp, data = bech32.bech32_decode(npub)
    if hrp != "npub" or data is None:
        return ""

    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None:
        return ""

    return bytes(decoded).hex()


def _get_nostr_pubkey_hex_for_name(name: str) -> str:
    identity = _get_identity_entry(name)
    if identity and identity.get("nostr_pubkey"):
        return identity["nostr_pubkey"]

    return _get_nostr_pubkey_hex_for_name_from_env(name)

def _get_nostr_pubkey_hex_for_name_from_env(name: str) -> str:
    return NOSTR_NAME_MAP.get(name.strip().lower(), "")

def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _parse_zap_request(nostr_raw: str, expected_pubkey_hex: str, amount_msat: int) -> dict[str, Any]:
    try:
        event = json.loads(nostr_raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid nostr zap request JSON: {exc}") from exc

    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Invalid nostr zap request")

    if event.get("kind") != 9734:
        raise HTTPException(status_code=400, detail="Invalid zap request kind")

    tags = event.get("tags") or []
    if not isinstance(tags, list):
        raise HTTPException(status_code=400, detail="Invalid zap request tags")

    p_tags = [t for t in tags if isinstance(t, list) and len(t) >= 2 and t[0] == "p"]
    if not p_tags:
        raise HTTPException(status_code=400, detail="Zap request missing p tag")

    p_value = str(p_tags[0][1]).strip().lower()
    if expected_pubkey_hex and p_value != expected_pubkey_hex.lower():
        raise HTTPException(status_code=400, detail="Zap request p tag does not match recipient")

    amount_tags = [t for t in tags if isinstance(t, list) and len(t) >= 2 and t[0] == "amount"]
    if amount_tags:
        try:
            tagged_amount = int(str(amount_tags[0][1]).strip())
            if tagged_amount != amount_msat:
                raise HTTPException(status_code=400, detail="Zap request amount does not match callback amount")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid zap request amount tag")

    return event

def _load_nostr_name_map():
    raw = NOSTR_NAME_MAP

    if isinstance(raw, dict):
        out = {}
        for k, v in raw.items():
            key = str(k).strip().lower()
            val = str(v).strip()
            if key and val:
                out[key] = val
        return out

    result = {}
    for pair in str(raw or "").split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, npub = pair.split(":", 1)
        name = name.strip().lower()
        npub = npub.strip()
        if name and npub:
            result[name] = npub
    return result


NOSTR_NAME_MAP = _get_setting("NOSTR_NAME_MAP", "nostr", "name_map", default={})

app = FastAPI(
    title="LNDK Backend",
    version="0.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- Identity Config (Nostr / NIP-05 / Zap) -------------------------------

class IdentityConfigPayload(BaseModel):
    alias: str
    nostr_pubkey: str
    relays: list[str] | None = None
    nip05_enabled: bool = True
    zap_enabled: bool = True


def _normalize_nostr_pubkey(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""

    if v.startswith("npub"):
        return _npub_to_hex_pubkey(v)

    if len(v) != 64:
        raise ValueError("Nostr Pubkey muss 64-stelliger HEX-Key oder npub sein.")

    try:
        bytes.fromhex(v)
    except Exception:
        raise ValueError("Ungültiger HEX-Pubkey.")

    return v.lower()


def _get_identity_map() -> dict[str, dict]:
    cfg = load_config()
    identity_map = cfg.get("identity_map", {})
    return identity_map if isinstance(identity_map, dict) else {}


def _save_identity_map(data: dict[str, dict]) -> None:
    cfg = load_config()
    cfg["identity_map"] = data
    save_config(cfg)


def _get_identity_entry(alias: str) -> dict:
    alias = (alias or "").strip().lower()
    if not alias:
        return {}
    return _get_identity_map().get(alias, {})


def _get_nostr_identity_for_name(name: str) -> dict:
    username = (name or "").strip().lower()
    if not username:
        return {}

    entry = _get_identity_entry(username)
    if entry:
        return {
            "alias": username,
            "nostr_pubkey": str(entry.get("nostr_pubkey", "")).strip().lower(),
            "relays": _normalize_relays(entry.get("relays") or _effective_default_nostr_relays()),
            "nip05_enabled": bool(entry.get("nip05_enabled", True)),
            "zap_enabled": bool(entry.get("zap_enabled", True)),
            "source": "config",
        }

    # Fallback auf bestehende ENV-Map
    env_pub = _get_nostr_pubkey_hex_for_name_from_env(username)
    if env_pub:
        return {
            "alias": username,
            "nostr_pubkey": env_pub,
            "relays": _normalize_relays(_effective_default_nostr_relays()),
            "nip05_enabled": True,
            "zap_enabled": True,
            "source": "env",
        }

    return {}


@app.get("/api/identity-config")
async def get_identity_config(alias: str):
    alias = (alias or "").strip().lower()
    if not alias:
        raise HTTPException(status_code=400, detail="alias is required")

    entry = _get_identity_entry(alias)
    if not entry:
        return {
            "alias": alias,
            "nostr_pubkey": "",
            "relays": _normalize_relays(_effective_default_nostr_relays()),
            "nip05_enabled": True,
            "zap_enabled": True,
            "exists": False,
        }

    return {
        "alias": alias,
        "nostr_pubkey": str(entry.get("nostr_pubkey", "")).strip(),
        "relays": _normalize_relays(entry.get("relays") or _effective_default_nostr_relays()),
        "nip05_enabled": bool(entry.get("nip05_enabled", True)),
        "zap_enabled": bool(entry.get("zap_enabled", True)),
        "exists": True,
    }


@app.post("/api/identity-config")
async def save_identity_config(payload: IdentityConfigPayload):
    alias = (payload.alias or "").strip().lower()
    if not alias:
        raise HTTPException(status_code=400, detail="alias is required")

    try:
        normalized_pubkey = _normalize_nostr_pubkey(payload.nostr_pubkey)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    relays = [str(x).strip() for x in (payload.relays or []) if str(x).strip()]

    identity_map = _get_identity_map()
    identity_map[alias] = {
        "nostr_pubkey": normalized_pubkey,
        "relays": relays,
        "nip05_enabled": bool(payload.nip05_enabled),
        "zap_enabled": bool(payload.zap_enabled),
    }
    _save_identity_map(identity_map)

    return {
        "alias": alias,
        "nostr_pubkey": normalized_pubkey,
        "relays": relays,
        "nip05_enabled": bool(payload.nip05_enabled),
        "zap_enabled": bool(payload.zap_enabled),
        "saved": True,
    }

# --- End Identity Config ---------------------------------------------------

# --- Helpers ----------------------------------------------------------------
def _base_command() -> list[str]:
    return [
        LNDK_CLI,
        "--network",
        LNDK_NETWORK,
        "--grpc-host",
        LNDK_GRPC_HOST,
        "--grpc-port",
        LNDK_GRPC_PORT,
        "--cert-path",
        LNDK_CERT_PATH,
        "--macaroon-path",
        LNDK_MACAROON_PATH,
    ]


def _run_command(args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"lndk-cli not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="lndk-cli timed out") from exc

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        message = stderr or stdout or f"lndk-cli failed with exit code {result.returncode}"
        raise HTTPException(status_code=502, detail=message)

    return stdout or stderr


def _extract_offer(raw_output: str) -> str:
    match = OFFER_RE.search(raw_output)
    if match:
        return match.group("offer")

    for line in raw_output.splitlines():
        line = line.strip().strip('"')
        if line.startswith("lno"):
            return line

    raise HTTPException(status_code=500, detail="Could not parse offer from lndk-cli output")


def _extract_offer_from_txt_record(txt_value: str) -> Optional[str]:
    value = txt_value.strip().strip('"').strip()
    if not value:
        return None

    if value.startswith("lno"):
        return value

    if value.lower().startswith("bitcoin:"):
        parsed = urlparse(value)
        offer_values = parse_qs(parsed.query).get("lno", [])
        if offer_values:
            offer = offer_values[0].strip()
            return offer if offer.startswith("lno") else None

        payload = value[len("bitcoin:") :].strip()
        if payload.startswith("lno"):
            return payload

    return None


def _new_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = DNS_RESOLVER_LIFETIME
    resolver.timeout = DNS_RESOLVER_TIMEOUT
    return resolver


_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    result: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        if value < 0 or (value >> frombits):
            raise HTTPException(status_code=400, detail="Invalid data for bit conversion")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)

    if pad:
        if bits:
            result.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise HTTPException(status_code=400, detail="Invalid LNURL padding")

    return result

def _lnd_rest_verify_setting():
    if LND_REST_INSECURE:
        return False
    return LND_TLS_CERT_PATH

def _encode_lnurl(url: str) -> str:
    if not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="LNURL target must be an https URL")

    hrp = "lnurl"
    data = _convertbits(url.encode("utf-8"), 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_ALPHABET[d] for d in data + checksum)

def _lnurl_metadata_for_alias(alias: dict[str, Any]) -> str:
    return _lnurl_metadata_json(alias["identifier"], alias["description"])

def _resolve_bip353_address(address: str) -> str:
    if not HRN_RE.match(address):
        raise HTTPException(status_code=400, detail="Invalid human-readable address format")

    user, domain = address.split("@", 1)

    candidate_fqdns = [
        f"{user}.user._bitcoin-payment.{domain}",
        f"{user}._bitcoin-payment.{domain}",
    ]

    resolver = _new_resolver()
    last_lookup_error: Optional[Exception] = None
    seen_txt_candidates: list[str] = []

    for fqdn in candidate_fqdns:
        try:
            answers = resolver.resolve(fqdn, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            last_lookup_error = exc
            continue
        except dns.exception.Timeout as exc:
            raise HTTPException(status_code=504, detail=f"DNS lookup timed out for {address}") from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"DNS lookup failed for {address}: {exc}") from exc

        for answer in answers:
            if hasattr(answer, "strings"):
                txt_value = "".join(
                    part.decode("utf-8") if isinstance(part, (bytes, bytearray)) else str(part)

                    for part in answer.strings
                )
            else:
                txt_value = str(answer).replace('"', "")

            seen_txt_candidates.append(txt_value)

            offer = _extract_offer_from_txt_record(txt_value)
            if offer:
                return offer

    if last_lookup_error is not None and not seen_txt_candidates:
        raise HTTPException(
            status_code=404,
            detail=f"No BIP353 TXT record found for {address}. Tried: {', '.join(candidate_fqdns)}",
        ) from last_lookup_error

    raise HTTPException(
        status_code=422,
        detail=(
            f"TXT records for {address} did not contain a usable lno offer. "
            f"Tried: {', '.join(candidate_fqdns)} | Seen TXT: {seen_txt_candidates}"
        ),
    )


def _normalize_offer_or_hrn(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("lno"):
        return candidate
    if HRN_RE.match(candidate):
        return _resolve_bip353_address(candidate)
    raise HTTPException(
        status_code=400,
        detail="Value must be either an lno... offer or a user@domain BIP353 address",
    )


def build_bip353_txt_value(offer: str) -> str:
    clean_offer = offer.strip()
    if not clean_offer.startswith("lno"):
        raise HTTPException(status_code=400, detail="Offer must start with lno")
    return f'"bitcoin:?lno={clean_offer}"'


def _normalize_lnurl_username(username: str) -> str:
    user = username.strip().lower()
    if not LNURL_USERNAME_RE.fullmatch(user):
        raise HTTPException(status_code=400, detail="Invalid LNURL username")
    return user


def _parse_lnurl_alias_map() -> dict[str, dict[str, Any]]:
    if not LNURL_ALIAS_MAP_RAW:
        return {}

    try:
        raw = json.loads(LNURL_ALIAS_MAP_RAW)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid LNURL_ALIAS_MAP JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError("LNURL_ALIAS_MAP must be a JSON object")

    parsed: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        username = _normalize_lnurl_username(str(key))

        if isinstance(value, str):
            parsed[username] = {"description": value.strip() or LNURL_DEFAULT_DESCRIPTION}
            continue

        if not isinstance(value, dict):
            raise RuntimeError(f"LNURL alias '{username}' must be a string or object")

        description = str(value.get("description", LNURL_DEFAULT_DESCRIPTION)).strip() or LNURL_DEFAULT_DESCRIPTION
        fixed_amount_sat = value.get("fixed_amount_sat")

        if fixed_amount_sat is not None:
            try:
                fixed_amount_sat = int(fixed_amount_sat)
            except Exception as exc:
                raise RuntimeError(f"LNURL alias '{username}' fixed_amount_sat must be an integer") from exc
            if fixed_amount_sat < 1:
                raise RuntimeError(f"LNURL alias '{username}' fixed_amount_sat must be >= 1")

        parsed[username] = {
            "description": description,
            "fixed_amount_sat": fixed_amount_sat,
        }

    return parsed


try:
    LNURL_ALIAS_MAP = _parse_lnurl_alias_map()
except RuntimeError as exc:
    raise RuntimeError(str(exc)) from exc


def _lnurl_identifier(username: str) -> str:
    return f"{username}@{get_lnurl_base_domain()}"

ASSETS_DIR = Path("/app/assets")
LNURL_LOGO_PATH = ASSETS_DIR / "lnurl-logo.png"
APP_ICON_PATH = ASSETS_DIR / "icon.png"


def _read_base64_file(path: Path) -> str:
    if not path.exists():
        return ""
    return base64.b64encode(path.read_bytes()).decode("ascii")


def get_lnurl_logo_base64() -> str:
    return _read_base64_file(LNURL_LOGO_PATH)


def get_app_icon_url() -> str:
    return "/assets/icon.png" if APP_ICON_PATH.exists() else ""

def _lnurl_metadata_json(identifier: str, description: str) -> str:
    logo_b64 = get_lnurl_logo_base64()

    metadata = [
        ["text/plain", description],
        ["text/identifier", identifier],
    ]

    if logo_b64:
        metadata.append(["image/png;base64", logo_b64])

    return json.dumps(
        metadata,
        separators=(",", ":"),
        ensure_ascii=False,
    )

def _resolve_lnurl_alias(username: str) -> dict[str, Any]:
    user = _normalize_lnurl_username(username)
    identifier = _lnurl_identifier(user)

    alias_entry = LNURL_ALIAS_MAP.get(user)
    if alias_entry is not None:
        description = alias_entry.get("description", LNURL_DEFAULT_DESCRIPTION)
        fixed_amount_sat = alias_entry.get("fixed_amount_sat")
        return {
            "username": user,
            "identifier": identifier,
            "description": description,
            "fixed_amount_sat": fixed_amount_sat,
        }

    if LNURL_ALIAS_MODE == "open":
        return {
            "username": user,
            "identifier": identifier,
            "description": f"{LNURL_DEFAULT_DESCRIPTION}: {identifier}",
            "fixed_amount_sat": None,
        }

    if LNURL_ALIAS_MODE == "shared":
        return {
            "username": user,
            "identifier": identifier,
            "description": LNURL_SHARED_DESCRIPTION,
            "fixed_amount_sat": None,
        }

    raise HTTPException(status_code=404, detail=f"LNURL alias not found: {user}")


def _lnurl_callback_url(username: str) -> str:
    return f"{get_lnurl_base_url()}/api/lnurl/callback/{username}"


def _read_macaroon_hex(path: str) -> str:
    try:
        return Path(path).read_bytes().hex()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"macaroon file not found: {path}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"failed to read macaroon file: {exc}") from exc
def get_lnurl_base_domain():
    cfg = load_config()
    return (cfg.get("lnurl_base_domain") or "").strip().lower() or LNURL_BASE_DOMAIN


def get_lnurl_base_url():
    cfg = load_config()
    return (cfg.get("lnurl_base_url") or "").strip().rstrip("/") or LNURL_BASE_URL

async def _create_bolt11_invoice(
    *,
    amount_sat: int,
    memo: str = "",
    expiry: int = 3600,
    description_hash: Optional[str] = None,
) -> dict[str, Any]:
    macaroon_hex = _read_macaroon_hex(LND_MACAROON_PATH)

    headers = {
        "Grpc-Metadata-macaroon": macaroon_hex,
        "Content-Type": "application/json",
    }

    payload: dict[str, Any] = {
        "value": str(amount_sat),
        "expiry": str(expiry),
    }

    if memo:
        payload["memo"] = memo

    if description_hash:
        payload["description_hash"] = description_hash

    verify = False if LND_REST_INSECURE else LND_TLS_CERT_PATH

    try:
        async with httpx.AsyncClient(timeout=LND_REST_TIMEOUT, verify=verify) as client:
            response = await client.post(
                f"{LND_REST_URL}/v1/invoices",
                headers=headers,
                json=payload,
            )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LND REST invoice request failed: {exc}") from exc

    try:
        data = response.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LND REST returned invalid JSON")

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LND REST invoice error: {data}")

    payment_request = data.get("payment_request") or data.get("paymentRequest")
    payment_hash = data.get("r_hash") or data.get("rHash") or ""

    if not payment_request:
        raise HTTPException(status_code=502, detail=f"LND REST invoice missing payment_request: {data}")

    return {
        "payment_request": payment_request,
        "payment_hash": payment_hash,
        "raw": data,
    }


async def _pay_bolt11_invoice(
    *,
    payment_request: str,
    fee_limit_sat: int | None = None,
) -> dict[str, Any]:
    macaroon_hex = _read_macaroon_hex(LND_MACAROON_PATH)

    headers = {
        "Grpc-Metadata-macaroon": macaroon_hex,
        "Content-Type": "application/json",
    }

    payload: dict[str, Any] = {
        "payment_request": payment_request,
    }

    if fee_limit_sat is not None and fee_limit_sat > 0:
        payload["fee_limit_sat"] = str(fee_limit_sat)

    verify = False if LND_REST_INSECURE else LND_TLS_CERT_PATH

    try:
        async with httpx.AsyncClient(timeout=LND_REST_TIMEOUT, verify=verify) as client:
            response = await client.post(
                f"{LND_REST_URL}/v1/channels/transactions",
                headers=headers,
                json=payload,
            )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LND REST payment request failed: {exc}") from exc

    raw_text = (response.text or "").strip()

    try:
        data = response.json()
    except Exception:
        data = None

    combined_error = ""

    if isinstance(data, dict):
        message_text = data.get("message") or ""
        payment_error = data.get("payment_error") or data.get("paymentError") or ""
        failure_reason = data.get("failure_reason") or data.get("failureReason") or ""
        combined_error = f"{message_text} {payment_error} {failure_reason} {raw_text}".strip().lower()
    else:
        combined_error = raw_text.lower()

    if "already paid" in combined_error:
        raise HTTPException(status_code=400, detail="Diese Rechnung wurde bereits bezahlt.")

    if "self payment" in combined_error or "self-payments not allowed" in combined_error:
        raise HTTPException(status_code=400, detail="Selbstzahlungen sind nicht erlaubt.")

    if "no route" in combined_error:
        raise HTTPException(status_code=400, detail="Keine Route gefunden.")

    if "insufficient balance" in combined_error:
        raise HTTPException(status_code=400, detail="Nicht genügend Guthaben.")

    if "timeout" in combined_error:
        raise HTTPException(status_code=400, detail="Zahlung hat zu lange gedauert.")

    if response.status_code >= 400:
        if isinstance(data, dict):
            detail = data.get("message") or data.get("detail") or data.get("payment_error") or data.get("failure_reason") or raw_text
        else:
            detail = raw_text or f"LND REST payment failed with HTTP {response.status_code}"
        raise HTTPException(status_code=502, detail=str(detail))

    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail=f"LND REST payment returned non-JSON: {raw_text[:300]}")

    payment_error = data.get("payment_error") or data.get("paymentError") or ""
    failure_reason = data.get("failure_reason") or data.get("failureReason") or ""

    if payment_error:
        raise HTTPException(status_code=400, detail=str(payment_error))

    if failure_reason and str(failure_reason).lower() not in {"failure_reason_none", "none", ""}:
        raise HTTPException(status_code=400, detail=str(failure_reason))

    return data


async def _resolve_lnurl_invoice(
    *,
    target: str,
    amount_sat: int,
    payer_note: Optional[str] = None,
) -> dict[str, Any]:
    target = target.strip()

    if not target or "@" not in target:
        raise HTTPException(status_code=400, detail="Invalid lightning address")

    username, domain = target.split("@", 1)
    username = username.strip()
    domain = domain.strip()

    if not username or not domain:
        raise HTTPException(status_code=400, detail="Invalid lightning address")

    lnurlp_url = f"https://{domain}/.well-known/lnurlp/{username}"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            meta_resp = await client.get(lnurlp_url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LNURL metadata request failed: {exc}") from exc

    try:
        meta = meta_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LNURL metadata returned invalid JSON")

    if meta_resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LNURL metadata error: {meta}")

    callback = meta.get("callback")
    min_sendable = int(meta.get("minSendable") or 0)
    max_sendable = int(meta.get("maxSendable") or 0)
    comment_allowed = int(meta.get("commentAllowed") or 0)

    if not callback:
        raise HTTPException(status_code=502, detail=f"LNURL metadata missing callback: {meta}")

    amount_msat = amount_sat * 1000

    if min_sendable and amount_msat < min_sendable:
        raise HTTPException(
            status_code=400,
            detail=f"Amount too low for LNURL target. Minimum is {min_sendable // 1000} sats.",
        )

    if max_sendable and amount_msat > max_sendable:
        raise HTTPException(
            status_code=400,
            detail=f"Amount too high for LNURL target. Maximum is {max_sendable // 1000} sats.",
        )

    params = {"amount": str(amount_msat)}
    if payer_note and comment_allowed > 0:
        params["comment"] = payer_note[:comment_allowed]

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            invoice_resp = await client.get(callback, params=params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LNURL callback request failed: {exc}") from exc

    try:
        invoice_data = invoice_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LNURL callback returned invalid JSON")

    if invoice_resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LNURL callback error: {invoice_data}")

    if invoice_data.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=invoice_data.get("reason") or "LNURL returned error")

    payment_request = invoice_data.get("pr")
    if not payment_request:
        raise HTTPException(status_code=502, detail=f"LNURL callback missing invoice: {invoice_data}")

    return {
        "lnurlp_url": lnurlp_url,
        "callback": callback,
        "payment_request": payment_request,
        "metadata": meta,
        "invoice_data": invoice_data,
    }


def _decode_lnurl_bech32(lnurl: str) -> str:
    lnurl = lnurl.strip().lower()
    hrp, data = bech32.bech32_decode(lnurl)
    if hrp != "lnurl" or data is None:
        raise HTTPException(status_code=400, detail="Ungültiger LNURL-String.")

    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None:
        raise HTTPException(status_code=400, detail="LNURL konnte nicht dekodiert werden.")

    try:
        return bytes(decoded).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"LNURL URL decode failed: {exc}") from exc
def _extract_lnurl_metadata_info(metadata_raw: Any) -> dict[str, Any]:
    text_plain = ""
    image_data_url = ""
    entries: list[Any] = []

    if isinstance(metadata_raw, str):
        try:
            entries = json.loads(metadata_raw)
        except Exception:
            entries = []
    elif isinstance(metadata_raw, list):
        entries = metadata_raw

    for item in entries:
        if not isinstance(item, list) or len(item) != 2:
            continue
        k, v = item[0], item[1]
        if k == "text/plain" and isinstance(v, str):
            text_plain = v
        elif isinstance(k, str) and k.startswith("image/") and isinstance(v, str):
            if ";base64" in k:
                mime = k.split(";")[0]
                image_data_url = f"data:{mime};base64,{v}"
            else:
                image_data_url = f"data:{k},{v}"

    return {
        "text_plain": text_plain,
        "image_data_url": image_data_url,
        "raw": metadata_raw,
    }


async def _fetch_lnurl_metadata_from_url(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LNURL metadata request failed: {exc}") from exc

    try:
        data = resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LNURL metadata returned invalid JSON")

    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LNURL metadata error: {data}")

    return data


def _lightning_address_to_lnurlp_url(target: str) -> str:
    target = target.strip()
    if "@" not in target:
        raise HTTPException(status_code=400, detail="Invalid lightning address")

    username, domain = target.split("@", 1)
    username = username.strip()
    domain = domain.strip()

    if not username or not domain:
        raise HTTPException(status_code=400, detail="Invalid lightning address")

    return f"https://{domain}/.well-known/lnurlp/{username}"

async def _resolve_lnurl_bech32_invoice(
    *,
    lnurl: str,
    amount_sat: int,
    comment: Optional[str] = None,
) -> dict[str, Any]:
    url = _decode_lnurl_bech32(lnurl)

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            meta_resp = await client.get(url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LNURL metadata request failed: {exc}") from exc

    try:
        meta = meta_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LNURL metadata returned invalid JSON")

    if meta_resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LNURL metadata error: {meta}")

    callback = meta.get("callback")
    min_sendable = int(meta.get("minSendable") or 0)
    max_sendable = int(meta.get("maxSendable") or 0)
    comment_allowed = int(meta.get("commentAllowed") or 0)

    if not callback:
        raise HTTPException(status_code=502, detail=f"LNURL metadata missing callback: {meta}")

    amount_msat = amount_sat * 1000

    if min_sendable and amount_msat < min_sendable:
        raise HTTPException(
            status_code=400,
            detail=f"Amount too low for LNURL target. Minimum is {min_sendable // 1000} sats.",
        )

    if max_sendable and amount_msat > max_sendable:
        raise HTTPException(
            status_code=400,
            detail=f"Amount too high for LNURL target. Maximum is {max_sendable // 1000} sats.",
        )

    params = {"amount": str(amount_msat)}
    if comment and comment_allowed > 0:
        params["comment"] = comment[:comment_allowed]

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            invoice_resp = await client.get(callback, params=params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LNURL callback request failed: {exc}") from exc

    try:
        invoice_data = invoice_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="LNURL callback returned invalid JSON")

    if invoice_resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"LNURL callback error: {invoice_data}")

    if invoice_data.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=invoice_data.get("reason") or "LNURL returned error")

    payment_request = invoice_data.get("pr")
    if not payment_request:
        raise HTTPException(status_code=502, detail=f"LNURL callback missing invoice: {invoice_data}")

    return {
        "lnurl_url": url,
        "callback": callback,
        "payment_request": payment_request,
        "metadata": meta,
        "invoice_data": invoice_data,
    }

def get_bip353_base_domain():
    cfg = load_config()

    # 1. explizit gesetzt
    cfg_domain = str(cfg.get("bip353_base_domain", "")).strip().lower()
    if cfg_domain:
        return cfg_domain

    # 2. aus public address ableiten (WICHTIG!)
    public_addr = str(cfg.get("public_bolt12_address", "")).strip().lower()
    if "@" in public_addr:
        return public_addr.split("@", 1)[1]

    # 3. ENV fallback
    env_domain = os.environ.get("BIP353_BASE_DOMAIN", "").strip().lower()
    if env_domain:
        return env_domain

    # 4. legacy fallback
    env_addr = os.environ.get("PUBLIC_BIP353_ADDRESS", "").strip().lower()
    if "@" in env_addr:
        return env_addr.split("@", 1)[1]

    return ""

def _build_lnurl_info_for_address(address: str) -> dict[str, str]:
    normalized = (address or "").strip().lower()
    if not HRN_RE.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid lightning address")

    username, domain = normalized.split("@", 1)
    lnurlp_url = f"https://{domain}/.well-known/lnurlp/{username}"
    lnurl = _encode_lnurl(lnurlp_url)

    return {
        "lightning_address": normalized,
        "lnurlp_url": lnurlp_url,
        "lnurl": lnurl,
    }

def _normalize_alias_name(name: str) -> str:
    alias = name.strip().lower()
    if not LNURL_USERNAME_RE.fullmatch(alias):
        raise HTTPException(status_code=400, detail="Invalid alias name")
    return alias


def _alias_address(name: str) -> str:
    return f"{name}@{get_lnurl_base_domain()}"


def _alias_dns_name(name: str) -> str:
    cf = get_cloudflare_config()
    zone_name = cf["zone_name"] or get_lnurl_base_domain()
    return f"{name}.user._bitcoin-payment.{zone_name}"

def _build_alias_response(name: str, alias_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "address": _alias_address(name),
        "description": alias_data.get("description", "Lightning payment"),
        "amount_sat": alias_data.get("amount_sat"),
        "dns_name": alias_data.get("dns_name"),
        "dns_content": alias_data.get("dns_content"),
        "published": bool(alias_data.get("published", False)),
        "last_offer": alias_data.get("last_offer"),
    }

def _create_offer_internal(payload: OfferRequest) -> OfferResponse:
    args = _base_command() + ["create-offer", "--description", payload.description]

    effective_amount_sat = payload.amount if payload.amount is not None else 1
    args += ["--amount", str(effective_amount_sat * 1000)]

    if payload.issuer:
        args += ["--issuer", payload.issuer]
    if payload.expiry is not None:
        args += ["--expiry", str(payload.expiry)]
    if payload.quantity is not None:
        args += ["--quantity", str(payload.quantity)]

    raw_output = _run_command(args)
    offer = _extract_offer(raw_output)
    return OfferResponse(offer=offer, raw_output=raw_output)

def qr_data(data: str) -> str:
    qr = qrcode.make(data)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"

async def _cloudflare_upsert_txt_record(*, name: str, content: str) -> dict[str, Any]:
    cf = get_cloudflare_config()

    token = cf["api_token"]
    zone_id = cf["zone_id"]
    zone_name = cf["zone_name"]
    enabled = cf["enabled"]

    if not enabled:
        raise HTTPException(
            status_code=400,
            detail="Cloudflare integration is not enabled in app config",
        )

    if not token or not zone_id or not zone_name:
        raise HTTPException(
            status_code=500,
            detail="Cloudflare config missing: api_token, zone_id or zone_name",
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=20) as client:
        lookup_response = await client.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            params={"type": "TXT", "name": name},
        )

        try:
            lookup_data = lookup_response.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Cloudflare returned invalid lookup response")

        if lookup_response.status_code >= 400 or not lookup_data.get("success", False):
            raise HTTPException(status_code=502, detail=f"Cloudflare lookup error: {lookup_data}")

        existing = lookup_data.get("result", []) or []

        payload = {
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 1,
        }

        if existing:
            record_id = existing[0]["id"]
            response = await client.put(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
                headers=headers,
                json=payload,
            )
        else:
            response = await client.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                headers=headers,
                json=payload,
            )

    try:
        data = response.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Cloudflare returned invalid response")

    if response.status_code >= 400 or not data.get("success", False):
        raise HTTPException(status_code=502, detail=f"Cloudflare error: {data}")

    return data.get("result", {})
async def _cloudflare_delete_txt_record(*, name: str) -> dict[str, Any]:
    cf = get_cloudflare_config()

    token = cf["api_token"]
    zone_id = cf["zone_id"]
    zone_name = cf["zone_name"]
    enabled = cf["enabled"]

    if not enabled:
        raise HTTPException(
            status_code=400,
            detail="Cloudflare integration is not enabled in app config",
        )

    if not token or not zone_id or not zone_name:
        raise HTTPException(
            status_code=500,
            detail="Cloudflare config missing: api_token, zone_id or zone_name",
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=20) as client:
        lookup_response = await client.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            params={"type": "TXT", "name": name},
        )

        try:
            lookup_data = lookup_response.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Cloudflare returned invalid lookup response")

        if lookup_response.status_code >= 400 or not lookup_data.get("success", False):
            raise HTTPException(status_code=502, detail=f"Cloudflare lookup error: {lookup_data}")

        existing = lookup_data.get("result", []) or []
        deleted_ids = []

        for record in existing:
            record_id = record.get("id")
            if not record_id:
                continue

            response = await client.delete(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
                headers=headers,
            )

            try:
                data = response.json()
            except Exception:
                raise HTTPException(status_code=502, detail="Cloudflare returned invalid delete response")

            if response.status_code >= 400 or not data.get("success", False):
                raise HTTPException(status_code=502, detail=f"Cloudflare delete error: {data}")

            deleted_ids.append(record_id)

    return {
        "ok": True,
        "name": name,
        "deleted_record_ids": deleted_ids,
    }

# --- API -------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        ok=True,
        cli=LNDK_CLI,
        grpc_host=LNDK_GRPC_HOST,
        grpc_port=LNDK_GRPC_PORT,
        cert_path=LNDK_CERT_PATH,
        macaroon_path=LNDK_MACAROON_PATH,
        allow_pay_offer=ALLOW_PAY_OFFER,
    )


@app.get("/api/info", response_model=PublicInfoResponse)
def public_info() -> PublicInfoResponse:
    address = get_public_bolt12_address().strip()
    fallback_address = get_public_lnurl_address().strip()

    offer = _resolve_bip353_address(address)

    return PublicInfoResponse(
        address=address,
        fallback_address=fallback_address,
        offer=offer,
    )

@app.get("/api/lnurl/address/{address:path}", response_model=LnurlInfoResponse)
def lnurl_for_address(address: str) -> LnurlInfoResponse:
    clean_address = address.strip().lower()
    lnurlp_url = _lightning_address_to_lnurlp_url(clean_address)
    return LnurlInfoResponse(
        lightning_address=clean_address,
        lnurl=_encode_lnurl(lnurlp_url),
        lnurlp_url=lnurlp_url,
    )


@app.get("/.well-known/lnurlp/{username}", response_model=LnurlPayMetadataResponse)
def lnurl_pay_metadata(username: str) -> LnurlPayMetadataResponse:
    alias = _resolve_lnurl_alias(username)

    min_sendable = LNURL_MIN_SENDABLE_MSAT
    max_sendable = LNURL_MAX_SENDABLE_MSAT

    if alias["fixed_amount_sat"] is not None:
        fixed_msat = int(alias["fixed_amount_sat"]) * 1000
        min_sendable = fixed_msat
        max_sendable = fixed_msat

    return LnurlPayMetadataResponse(
        callback=_lnurl_callback_url(alias["username"]),
        minSendable=min_sendable,
        maxSendable=max_sendable,
        metadata=_lnurl_metadata_json(alias["identifier"], alias["description"]),
        commentAllowed=max(0, LNURL_COMMENT_ALLOWED),
        allowsNostr=True,
        nostrPubkey=_get_nostr_pubkey_hex_for_name(alias["username"]),
    )


@app.get("/api/lnurl/callback/{username}")
async def lnurl_callback(
    username: str,
    amount: int = Query(..., ge=1, description="Requested amount in millisatoshis"),
    comment: Optional[str] = Query(default=None),
    nostr: Optional[str] = Query(default=None),
    lnurl: Optional[str] = Query(default=None),
) -> dict[str, Any]:
    alias = _resolve_lnurl_alias(username)

    min_sendable = LNURL_MIN_SENDABLE_MSAT
    max_sendable = LNURL_MAX_SENDABLE_MSAT

    if alias["fixed_amount_sat"] is not None:
        fixed_msat = int(alias["fixed_amount_sat"]) * 1000
        min_sendable = fixed_msat
        max_sendable = fixed_msat

    if amount < min_sendable or amount > max_sendable:
        raise HTTPException(status_code=400, detail="amount outside configured LNURL min/max range")

    if comment and len(comment) > max(0, LNURL_COMMENT_ALLOWED):
        raise HTTPException(status_code=400, detail="comment too long")

    print(f"LNURL callback username={username} amount={amount} comment={comment!r}")
    amount_sat = max(1, math.ceil(amount / 1000))

    metadata = _lnurl_metadata_for_alias(alias)
    description_hash = hashlib.sha256(metadata.encode("utf-8")).digest()
    description_hash_b64 = base64.b64encode(description_hash).decode("ascii")

    memo = comment.strip() if comment else ""
    zap_request_event = None
    recipient_nostr_hex = _get_nostr_pubkey_hex_for_name(username)

    if nostr:
        zap_request_event = _parse_zap_request(
            nostr_raw=nostr,
            expected_pubkey_hex=recipient_nostr_hex,
            amount_msat=amount,
        )
        description_hash_b64 = _sha256_b64(nostr.encode("utf-8"))
        memo = ""

    invoice = await _create_bolt11_invoice(
        amount_sat=amount_sat,
        memo=memo,
        description_hash=description_hash_b64,
    )

    payment_request = invoice["payment_request"] if isinstance(invoice, dict) else str(invoice)
    # --- ZAP QUEUE STORE -----------------------------------------
    if nostr and zap_request_event:
        try:
            zap_request = json.loads(nostr)

            def _extract_relays(tags):
                for t in tags:
                    if isinstance(t, list) and len(t) > 1 and t[0] == "relays":
                        return t[1:]
                return []

            relays = _extract_relays(zap_request.get("tags", []))

            payment_hash = ""
            if isinstance(invoice, dict):
                payment_hash = str(invoice.get("payment_hash") or "").strip()

            if not payment_hash:
                raise ValueError("Invoice missing payment_hash")

            pending = _get_pending_zaps()

            pending[payment_hash] = {
                "created_at": int(time.time()),
                "recipient_pubkey_hex": recipient_nostr_hex,
                "payer_pubkey_hex": zap_request.get("pubkey"),
                "amount_msat": amount,
                "payment_request": payment_request,
                "relays": relays,
                "zap_request_event": zap_request,
                "comment": comment or "",
                "is_zap": bool(zap_request_event),
                "identifier": alias["identifier"],
                "published": False,
            }

            _save_pending_zaps(pending)
            print("zap queued:", payment_hash)

        except Exception as e:
            print("zap queue error:", e)
    # -------------------------------------------------------------
    success_message = f"Payment request for {alias['identifier']}"
    if comment:
        success_message = f"{success_message} • Comment: {comment}"
    if zap_request_event:
        success_message = f"Zap invoice for {alias['identifier']}"

    return {
        "pr": payment_request,
        "routes": [],
        "successAction": {
            "tag": "message",
            "message": success_message,
        },
        "disposable": False,
        "allowsNostr": True,
        "nostrPubkey": _get_nostr_pubkey_hex_for_name(username),
    }

@app.get("/api/setup/status")
def setup_status(request: StarletteRequest):
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")

    cfg = load_config()

    configured = bool(cfg.get("lnurl_base_domain"))

    return {
        "configured": configured
    }

@app.get("/api/setup/config")
def get_setup_config():
    return load_config()

from fastapi.staticfiles import StaticFiles

app.mount("/assets", StaticFiles(directory="/app/assets"), name="assets")

@app.post("/api/setup/config")
def set_setup_config(payload: dict):
    cfg = load_config()

    safe_payload = dict(payload or {})
    password = str(safe_payload.pop("password", "")).strip()

    cfg["public_bolt12_address"] = str(safe_payload.get("public_bolt12_address", "")).strip()
    cfg["public_lnurl_address"] = str(safe_payload.get("public_lnurl_address", "")).strip()
    cfg["lnurl_base_domain"] = str(safe_payload.get("lnurl_base_domain", "")).strip().lower()
    cfg["lnurl_base_url"] = str(safe_payload.get("lnurl_base_url", "")).strip().rstrip("/")

    dns_mode = str(safe_payload.get("dns_mode", "none")).strip().lower()
    cfg["dns_mode"] = dns_mode

    cf = safe_payload.get("cloudflare", {}) or {}
    cfg["cloudflare"] = {
        "enabled": bool(cf.get("enabled")) or dns_mode == "cloudflare",
        "zone_name": str(cf.get("zone_name", "")).strip(),
        "zone_id": str(cf.get("zone_id", "")).strip(),
        "api_token": str(cf.get("api_token", "")).strip(),
    }

    if password:
        cfg["ui_password_hash"] = _hash_password(password)

    save_config(cfg)

    return {"ok": True}
@app.post("/api/create-offer", response_model=OfferResponse)
def create_offer(payload: OfferRequest) -> OfferResponse:
    return _create_offer_internal(payload)


@app.post("/api/decode-offer", response_model=DecodeResponse)
def decode_offer(payload: DecodeRequest) -> DecodeResponse:
    normalized_offer = _normalize_offer_or_hrn(payload.offer)
    args = _base_command() + ["decode-offer", normalized_offer]
    raw_output = _run_command(args)
    return DecodeResponse(raw_output=raw_output)


@app.post("/api/pay-offer", response_model=PayOfferResponse)
def pay_offer(payload: PayOfferRequest) -> PayOfferResponse:
    if not ALLOW_PAY_OFFER:
        raise HTTPException(status_code=403, detail="pay-offer endpoint is disabled")

    normalized_offer = _normalize_offer_or_hrn(payload.offer)
    args = _base_command() + ["pay-offer", normalized_offer, str(payload.amount_sat * 1000)]

    if payload.payer_note:
        args.append(payload.payer_note)

    raw_output = _run_command(args)
    return PayOfferResponse(resolved_offer=normalized_offer, raw_output=raw_output)
@app.post("/api/pay-address", response_model=PayOfferResponse)
async def pay_address(payload: PayAddressRequest) -> PayOfferResponse:
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target required")

    try:
        normalized_offer = _normalize_offer_or_hrn(target)
        args = _base_command() + ["pay-offer", normalized_offer, str(payload.amount_sat * 1000)]

        if payload.payer_note:
            args.append(payload.payer_note)

        raw_cli_output = _run_command(args)

        raw_output = json.dumps(
            {
                "mode": "bip353",
                "target": target,
                "resolved_offer": normalized_offer,
                "raw_output": raw_cli_output,
            },
            indent=2,
            ensure_ascii=False,
        )

        return PayOfferResponse(resolved_offer=normalized_offer, raw_output=raw_output)

    except HTTPException as exc:
        message = str(exc.detail)

        if "No BIP353 TXT record found" not in message:
            raise

        lnurl_result = await _resolve_lnurl_invoice(
            target=target,
            amount_sat=payload.amount_sat,
            payer_note=payload.payer_note,
        )

        pay_result = await _pay_bolt11_invoice(
            payment_request=lnurl_result["payment_request"],
        )

        raw_output = json.dumps(
            {
                "mode": "lnurl",
                "target": target,
                "payment_request": lnurl_result["payment_request"],
                "lnurlp_url": lnurl_result["lnurlp_url"],
                "payment_result": pay_result,
            },
            indent=2,
            ensure_ascii=False,
        )

        return PayOfferResponse(
            resolved_offer=target,
            raw_output=raw_output,
        )
@app.post("/api/pay-bolt11", response_model=PayOfferResponse)
async def pay_bolt11(payload: PayBolt11Request) -> PayOfferResponse:

    invoice = payload.invoice.strip()
    if not invoice:
        raise HTTPException(status_code=400, detail="invoice required")

    result = await _pay_bolt11_invoice(payment_request=invoice)

    raw_output = json.dumps(
        {
            "mode": "bolt11",
            "invoice": invoice,
            "payment_result": result,
        },
        indent=2,
        ensure_ascii=False,
    )

    return PayOfferResponse(
        resolved_offer=invoice,
        raw_output=raw_output,
    )

class DecodeBolt11Request(BaseModel):
    invoice: str = Field(min_length=10, description="BOLT11 invoice like lnbc...")


class PreviewPayTargetRequest(BaseModel):
    target: str = Field(min_length=3, description="Lightning Address or lnurl1...")

class PayLnurlRequest(BaseModel):
    lnurl: str
    amount_sat: int
    comment: Optional[str] = None

@app.post("/api/preview-pay-target")
async def preview_pay_target(payload: PreviewPayTargetRequest):
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target required")

    lowered = target.lower()

    if lowered.startswith("lnbc") or lowered.startswith("lntb") or lowered.startswith("lnbcrt"):
        macaroon_hex = _read_macaroon_hex(LND_MACAROON_PATH)
        headers = {"Grpc-Metadata-macaroon": macaroon_hex}
        verify = False if LND_REST_INSECURE else LND_TLS_CERT_PATH

        try:
            async with httpx.AsyncClient(timeout=LND_REST_TIMEOUT, verify=verify) as client:
                response = await client.get(f"{LND_REST_URL}/v1/payreq/{target}", headers=headers)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"LND REST decodepayreq failed: {exc}") from exc

        try:
            data = response.json()
        except Exception:
            raise HTTPException(status_code=502, detail="LND REST decodepayreq returned invalid JSON")

        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"LND REST decodepayreq error: {data}")

        return {
            "kind": "bolt11",
            "title": "BOLT11 Invoice",
            "amount_sat": data.get("num_satoshis") or data.get("numSatoshis") or "",
            "description": data.get("description") or "",
            "destination": data.get("destination") or "",
            "image_data_url": "",
            "comment_allowed": 0,
            "min_sat": "",
            "max_sat": "",
        }

    if "@" in target and " " not in target:
        lnurlp_url = _lightning_address_to_lnurlp_url(target)
        meta = await _fetch_lnurl_metadata_from_url(lnurlp_url)
        meta_info = _extract_lnurl_metadata_info(meta.get("metadata"))

        return {
            "kind": "lightning_address",
            "title": "Lightning Address",
            "identifier": target,
            "description": meta_info["text_plain"] or meta.get("description", ""),
            "image_data_url": meta_info["image_data_url"],
            "comment_allowed": int(meta.get("commentAllowed") or 0),
            "min_sat": int(meta.get("minSendable") or 0) // 1000,
            "max_sat": int(meta.get("maxSendable") or 0) // 1000,
            "raw": meta,
        }

    if lowered.startswith("lnurl1"):
        url = _decode_lnurl_bech32(target)
        meta = await _fetch_lnurl_metadata_from_url(url)
        meta_info = _extract_lnurl_metadata_info(meta.get("metadata"))

        return {
            "kind": "lnurl",
            "title": "LNURL Pay",
            "identifier": target,
            "description": meta_info["text_plain"] or meta.get("description", ""),
            "image_data_url": meta_info["image_data_url"],
            "comment_allowed": int(meta.get("commentAllowed") or 0),
            "min_sat": int(meta.get("minSendable") or 0) // 1000,
            "max_sat": int(meta.get("maxSendable") or 0) // 1000,
            "raw": meta,
        }

    return {
        "kind": "unknown",
        "title": "",
        "description": "",
        "image_data_url": "",
        "comment_allowed": 0,
        "min_sat": "",
        "max_sat": "",
    }

@app.post("/api/pay-lnurl", response_model=PayOfferResponse)
async def pay_lnurl(payload: PayLnurlRequest) -> PayOfferResponse:
    result = await _resolve_lnurl_bech32_invoice(
        lnurl=payload.lnurl,
        amount_sat=payload.amount_sat,
        comment=payload.comment,
    )

    pay_result = await _pay_bolt11_invoice(
        payment_request=result["payment_request"],
    )

    raw_output = json.dumps(
        {
            "mode": "lnurl",
            "lnurl": payload.lnurl,
            "payment_request": result["payment_request"],
            "payment_result": pay_result,
        },
        indent=2,
        ensure_ascii=False,
    )

    return PayOfferResponse(
        resolved_offer=payload.lnurl,
        raw_output=raw_output,
    )

@app.post("/api/cloudflare/create-bip353")
async def create_cloudflare_bip353(req: CloudflareBIP353Request):
    record_name = req.record_name.strip().lower()
    if not record_name:
        raise HTTPException(status_code=400, detail="record_name required")

    txt_name = _alias_dns_name(record_name)
    txt_value = build_bip353_txt_value(req.offer)

    result = await _cloudflare_upsert_txt_record(name=txt_name, content=txt_value)

    cfg = load_config()
    public_bolt12_address = str(cfg.get("public_bolt12_address", "")).strip()

    human_readable_address = ""
    if "@" in public_bolt12_address:
        domain = public_bolt12_address.split("@", 1)[1].strip()
        if domain:
            human_readable_address = f"{record_name}@{domain}"

    return {
        "ok": True,
        "name": txt_name,
        "content": txt_value,
        "result": result,
        "human_readable_address": human_readable_address,
    }

@app.get("/api/alias")
def list_aliases():
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    return {
        "items": [
            _build_alias_response(name, alias_data)
            for name, alias_data in sorted(aliases.items())
        ]
    }


@app.get("/api/qr/{value}")
async def qr_code(value: str):
    img = qrcode.make(value)

    buf = BytesIO()
    img.save(buf, format="PNG")

    return Response(buf.getvalue(), media_type="image/png")

@app.post("/api/alias", response_model=AliasResponse)
def create_alias(payload: AliasCreateRequest):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    name = _normalize_alias_name(payload.name)

    aliases[name] = {
        "description": payload.description.strip(),
        "amount_sat": payload.amount_sat,
        "published": False,
        "dns_name": None,
        "dns_content": None,
        "last_offer": None,
    }

    cfg["aliases"] = aliases
    save_config(cfg)

    return _build_alias_response(name, aliases[name])


@app.delete("/api/alias/{name}")
async def delete_alias(name: str, delete_dns: bool = False):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    alias_name = _normalize_alias_name(name)

    if alias_name not in aliases:
        raise HTTPException(status_code=404, detail="Alias not found")

    deleted = aliases.pop(alias_name)
    cfg["aliases"] = aliases
    save_config(cfg)

    dns_result = None
    dns_name = deleted.get("dns_name")

    if delete_dns and dns_name and cfg.get("dns_mode") == "cloudflare":
        dns_result = await _cloudflare_delete_txt_record(name=dns_name)

    return {
        "ok": True,
        "deleted": _build_alias_response(alias_name, deleted),
        "dns_deleted": dns_result,
    }

@app.patch("/api/alias/{name}", response_model=AliasResponse)
def update_alias(name: str, payload: AliasUpdateRequest):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    alias_name = _normalize_alias_name(name)

    if alias_name not in aliases:
      raise HTTPException(status_code=404, detail="Alias not found")

    alias_data = aliases[alias_name]
    alias_data["description"] = payload.description.strip()
    alias_data["amount_sat"] = payload.amount_sat

    aliases[alias_name] = alias_data
    cfg["aliases"] = aliases
    save_config(cfg)

    return _build_alias_response(alias_name, alias_data)

@app.post("/api/create-invoice", response_model=CreateInvoiceResponse)
async def create_invoice(payload: CreateInvoiceRequest, request: StarletteRequest) -> CreateInvoiceResponse:
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    result = await _create_bolt11_invoice(
        amount_sat=payload.amount_sat,
        memo=payload.memo,
        expiry=payload.expiry or 3600,
    )

    return CreateInvoiceResponse(
        payment_request=result["payment_request"],
        payment_hash=result["payment_hash"],
        expires_at=None,
    )

@app.post("/api/alias/{name}/publish", response_model=AliasResponse)
async def publish_alias(name: str):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    alias_name = _normalize_alias_name(name)

    if alias_name not in aliases:
        raise HTTPException(status_code=404, detail="Alias not found")

    alias_data = aliases[alias_name]
    description = alias_data.get("description") or f"{alias_name}@{get_lnurl_base_domain()}"
    amount_sat = alias_data.get("amount_sat")

    offer_response = _create_offer_internal(
        OfferRequest(
            amount=amount_sat,
            description=description,
        )
    )

    dns_name = _alias_dns_name(alias_name)
    dns_content = build_bip353_txt_value(offer_response.offer)

    if cfg.get("dns_mode") == "cloudflare":
        await _cloudflare_upsert_txt_record(name=dns_name, content=dns_content)

    alias_data["published"] = True
    alias_data["dns_name"] = dns_name
    alias_data["dns_content"] = dns_content
    alias_data["last_offer"] = offer_response.offer

    aliases[alias_name] = alias_data
    cfg["aliases"] = aliases
    save_config(cfg)

    return _build_alias_response(alias_name, alias_data)
    from fastapi.responses import HTMLResponse

@app.post("/api/alias/{name}/refresh-offer", response_model=AliasResponse)
async def refresh_alias_offer(name: str):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    alias_name = _normalize_alias_name(name)

    if alias_name not in aliases:
        raise HTTPException(status_code=404, detail="Alias not found")

    alias_data = aliases[alias_name]
    description = alias_data.get("description") or f"{alias_name}@{get_lnurl_base_domain()}"
    amount_sat = alias_data.get("amount_sat")

    offer_response = _create_offer_internal(
        OfferRequest(
            amount=amount_sat,
            description=description,
        )
    )

    dns_name = _alias_dns_name(alias_name)
    dns_content = build_bip353_txt_value(offer_response.offer)

    if cfg.get("dns_mode") == "cloudflare":
        await _cloudflare_upsert_txt_record(name=dns_name, content=dns_content)

    alias_data["published"] = True
    alias_data["dns_name"] = dns_name
    alias_data["dns_content"] = dns_content
    alias_data["last_offer"] = offer_response.offer

    aliases[alias_name] = alias_data
    cfg["aliases"] = aliases
    save_config(cfg)

    return _build_alias_response(alias_name, alias_data)

@app.get("/", response_class=HTMLResponse)
@app.get("/links", response_class=HTMLResponse)
async def public_index_page():
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    items_html = ""
    for alias_name, alias in aliases.items():
        description = alias.get("description") or "Lightning payment"
        amount_sat = alias.get("amount_sat")
        amount_label = f"{amount_sat} sats" if amount_sat else "variable amount"

        items_html += f"""
        <div class="aliasCard">
          <div class="aliasTitle mono">{alias_name}@{get_lnurl_base_domain()}</div>
          <div class="aliasMeta">
            {description}<br />
            Amount: {amount_label}
          </div>
          <div class="row">
            <button onclick="window.location.href='/{alias_name}'">Open</button>
            <button class="secondary" onclick="copyWithToast('{alias_name}@{get_lnurl_base_domain()}', (T[getLang()] || T.en).addressCopied)">Copy address</button>
          </div>
        </div>
        """

    if not items_html:
        items_html = """
    <div class="aliasCard" data-empty-alias-list="1">
      <div class="aliasMeta">No public aliases available yet.</div>
    </div>
        """

    html = f"""
<!doctype html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="icon" href="/assets/icon.png" sizes="32x32" />
  <link rel="icon" href="/assets/icon.png" sizes="192x192" />
  <link rel="icon" href="/assets/icon.png" sizes="512x512" />
  <link rel="apple-touch-icon" href="/assets/icon.png" sizes="180x180" />
  <link rel="icon" href="/assets/icon.png" sizes="32x32" />
  <link rel="icon" href="/assets/icon.png" sizes="192x192" />
  <link rel="icon" href="/assets/icon.png" sizes="512x512" />
  <link rel="apple-touch-icon" href="/assets/icon.png" sizes="180x180" />
  <link rel="icon" href="/assets/icon.png" sizes="32x32" />
  <link rel="icon" href="/assets/icon.png" sizes="192x192" />
  <link rel="icon" href="/assets/icon.png" sizes="512x512" />
  <link rel="apple-touch-icon" href="/assets/icon.png" sizes="180x180" />
  <title>Lightning Payments</title>
  <style>
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #0b1220, #0f172a);
      color: #eef2ff;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 18px;
    }}
    .card {{
      width: 100%;
      max-width: 760px;
      background: rgba(18, 26, 43, 0.96);
      border: 1px solid #26324a;
      border-radius: 24px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, .35);
      padding: 24px;
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: 2rem;
      text-align: center;
    }}
    .sub {{
      color: #a7b0c3;
      margin-bottom: 20px;
      text-align: center;
      line-height: 1.5;
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      word-break: break-all;
    }}
    .aliasList {{
      display: grid;
      gap: 14px;
      margin-top: 18px;
    }}
    .aliasCard {{
      border: 1px solid #26324a;
      background: rgba(255,255,255,0.02);
      border-radius: 18px;
      padding: 16px;
    }}
    .aliasTitle {{
      font-weight: 700;
      font-size: 1rem;
      margin-bottom: 8px;
    }}
    .aliasMeta {{
      color: #a7b0c3;
      line-height: 1.5;
      margin-bottom: 12px;
    }}
    .row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: center;
    }}
    button {{
      appearance: none;
      border: 1px solid #f7931a;
      background: #f7931a;
      color: #091120;
      font-weight: 700;
      padding: 12px 16px;
      border-radius: 14px;
      cursor: pointer;
    }}
    button.secondary {{
      background: transparent;
      color: #eef2ff;
      border-color: #26324a;
    }}
  </style>
</head>
<body>
<main class="card">

  <div style="display:flex;justify-content:flex-end;margin-bottom:6px;">
    <div style="
      display:inline-flex;
      gap:4px;
      padding:4px;
      border-radius:16px;
      border:1px solid #26324a;
      background:rgba(19,28,46,.92);
    ">
      <button id="landingLangDe"
        style="
          min-width:36px;
          height:26px;
          padding:0 8px;
          border-radius:10px;
          border:none;
          background:transparent;
          color:#a7b0c3;
          font-size:.78rem;
          font-weight:700;
        "
      >DE</button>

      <button id="landingLangEn"
        style="
          min-width:36px;
          height:26px;
          padding:0 8px;
          border-radius:10px;
          font-size:.78rem;
          border:none;
          background:#3a4254;
          color:#eef2ff;
          font-weight:700;
        "
      >EN</button>
    </div>
  </div>
<div style="display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:14px;">
  <a href="{HOME_URL}" aria-label="Back to homepage" title="Back to homepage" style="display:inline-flex;align-items:center;justify-content:center;text-decoration:none;">
    <img
      src="/assets/icon.png"
      alt="BOLT12 Pay Server Logo"
      style="width:72px;height:72px;object-fit:contain;display:block;cursor:pointer;filter:drop-shadow(0 0 3px rgba(255,200,0,0.35));"
    >
  </a>
<h1 id="landingTitle" style="margin:0;">⚡ Lightning Payments</h1>
</div>
<div class="sub">
  <span id="landingSubtitle">Public payment pages on</span> <span class="mono">{get_lnurl_base_domain()}</span><br />
  <span id="landingSubline" style="font-size:.92rem;">BOLT12 • Lightning Address • BOLT11 fallback</span>
</div>
    <div class="row" style="margin-bottom: 18px;">
<button id="landingOpenApp" class="secondary" onclick="window.location.href='/app'">Open App</button>
<button id="landingOpenPay" class="secondary" onclick="window.location.href='/pay'">Open Pay</button>
<button id="landingSetup" class="secondary" onclick="window.location.href='/app?setup=1'">Setup Wizard</button>
    </div>
    <div class="aliasList">
      {items_html}
    </div>
  </main>
<script>
(function () {{
  const T = {{
    en: {{
      title: "⚡ Lightning Payments",
      subtitle: "Public payment pages on",
      subline: "BOLT12 • Lightning Address • BOLT11 fallback",
      openApp: "Open App",
      openPay: "Open Pay",
      setup: "Setup Wizard",
      empty: "No public aliases available yet."
    }},
    de: {{
      title: "⚡ Lightning Zahlungen",
      subtitle: "Öffentliche Zahlungsseiten auf",
      subline: "BOLT12 • Lightning Address • BOLT11 Fallback",
      openApp: "App öffnen",
      openPay: "Bezahlen öffnen",
      setup: "Setup Assistent",
      empty: "Noch keine öffentlichen Aliase vorhanden."
    }}
  }};
function getLang() {{
  const stored = localStorage.getItem("app_lang");
  if (stored) return stored;

  const nav = navigator.language || "";
  if (nav.startsWith("de")) return "de";

  return "en";
}}


  window.setLang = function (lang) {{
    localStorage.setItem("app_lang", lang);
    applyLang();
  }};

  function setActive(lang) {{
    const deBtn = document.getElementById("landingLangDe");
    const enBtn = document.getElementById("landingLangEn");
    if (!deBtn || !enBtn) return;

    const activeBg = "#3a4254";
    const activeColor = "#eef2ff";
    const idleBg = "transparent";
    const idleColor = "#a7b0c3";

    [deBtn, enBtn].forEach((btn) => {{
      btn.style.boxShadow = "none";
      btn.style.border = "none";
    }});

    if (lang === "de") {{
      deBtn.style.background = activeBg;
      deBtn.style.color = activeColor;
      enBtn.style.background = idleBg;
      enBtn.style.color = idleColor;
    }} else {{
      enBtn.style.background = activeBg;
      enBtn.style.color = activeColor;
      deBtn.style.background = idleBg;
      deBtn.style.color = idleColor;
    }}
  }}

  function applyLang() {{
    const lang = getLang();
    const t = T[lang] || T.en;

    const title = document.getElementById("landingTitle");
    const subtitle = document.getElementById("landingSubtitle");
    const subline = document.getElementById("landingSubline");
    const openApp = document.getElementById("landingOpenApp");
    const openPay = document.getElementById("landingOpenPay");
    const setup = document.getElementById("landingSetup");

    if (title) title.textContent = t.title;
    if (subtitle) subtitle.textContent = t.subtitle;
    if (subline) subline.textContent = t.subline;
    if (openApp) openApp.textContent = t.openApp;
    if (openPay) openPay.textContent = t.openPay;
    if (setup) setup.textContent = t.setup;

    const aliasList = document.querySelector(".aliasList");
    const emptyCard = aliasList ? aliasList.querySelector('[data-empty-alias-list="1"]') : null;
    if (emptyCard) {{
      emptyCard.innerHTML = '<div class="aliasMeta">' + t.empty + '</div>';
    }}

    setActive(lang);
  }}
  function applyAliasTooltips() {{
    const t = T[getLang()] || T.en;
    [
      "aliasBip353String",
      "aliasOfferString",
      "aliasLnurlString",
      "aliasBolt11String"
    ].forEach((id) => {{
      const el = document.getElementById(id);
      if (el) el.title = t.tapToCopy;
    }});
    [
      "aliasBip353Qr",
      "aliasOfferQr",
      "aliasLnurlQr",
      "aliasBolt11Qr"
    ].forEach((id) => {{
      const el = document.getElementById(id);
      if (el) el.title = t.tapQrToCopy;
    }});
  }}

  window.addEventListener("load", function () {{
    const deBtn = document.getElementById("landingLangDe");
    const enBtn = document.getElementById("landingLangEn");

    if (deBtn) deBtn.onclick = function () {{ window.setLang("de"); }};
    if (enBtn) enBtn.onclick = function () {{ window.setLang("en"); }};
    applyLang();
  }});
}})();
</script>
</body>
</html>
"""
    return HTMLResponse(html)



def _no_store_headers(extra: Optional[dict] = None) -> dict:
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    if extra:
        headers.update(extra)
    return headers


def _base32_normalize(secret: str) -> str:
    return secret.strip().replace(" ", "").upper()


def _totp_now(secret: str, timestep: int = 30, digits: int = 6) -> str:
    secret = _base32_normalize(secret)
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(time.time() // timestep)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


def _verify_totp(secret: str, code: str, window: int = 1, timestep: int = 30, digits: int = 6) -> bool:
    secret = _base32_normalize(secret)
    code = (code or "").strip().replace(" ", "")
    if not secret:
        return True
    if not code or not code.isdigit():
        return False

    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    now_counter = int(time.time() // timestep)

    for delta in range(-window, window + 1):
        counter = now_counter + delta
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        candidate = str(code_int % (10 ** digits)).zfill(digits)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def _create_pay_session() -> str:
    token = secrets.token_urlsafe(32)
    PAY_SESSIONS[token] = {
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + PAY_UI_SESSION_TTL,
    }
    return token


def _cleanup_pay_sessions() -> None:
    now = int(time.time())
    expired = [token for token, meta in PAY_SESSIONS.items() if int(meta.get("expires_at", 0)) <= now]
    for token in expired:
        PAY_SESSIONS.pop(token, None)


def _get_pay_session_token(request: StarletteRequest) -> Optional[str]:
    return request.cookies.get(PAY_UI_COOKIE_NAME)


def _is_pay_session_valid(request: StarletteRequest) -> bool:
    _cleanup_pay_sessions()
    token = _get_pay_session_token(request)
    if not token:
        return False
    meta = PAY_SESSIONS.get(token)
    if not meta:
        return False
    if int(meta.get("expires_at", 0)) <= int(time.time()):
        PAY_SESSIONS.pop(token, None)
        return False
    return True


def require_pay_auth(request: Request) -> None:
    if not _is_pay_ui_configured():
        raise HTTPException(
            status_code=403,
            detail="Pay UI setup incomplete. Please set an admin password first.",
        )
    if not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")


def _issue_nwc_session() -> tuple[str, int]:
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    expires_at = now + NWC_SESSION_TTL
    NWC_SESSIONS[token] = {
        "created_at": now,
        "expires_at": expires_at,
    }
    return token, expires_at


def _cleanup_nwc_sessions() -> None:
    now = int(time.time())
    expired = [token for token, meta in NWC_SESSIONS.items() if int(meta.get("expires_at", 0)) <= now]
    for token in expired:
        NWC_SESSIONS.pop(token, None)


def _get_nwc_session_token(request: StarletteRequest) -> Optional[str]:
    return request.cookies.get(NWC_COOKIE_NAME)


def _read_nwc_session_token(request: StarletteRequest) -> Optional[str]:
    return _get_nwc_session_token(request)


def _is_nwc_session_valid(request: StarletteRequest) -> bool:
    _cleanup_nwc_sessions()
    token = _get_nwc_session_token(request)
    if not token:
        return False
    meta = NWC_SESSIONS.get(token)
    if not meta:
        return False
    if int(meta.get("expires_at", 0)) <= int(time.time()):
        NWC_SESSIONS.pop(token, None)
        return False
    return True


def require_nwc_auth(request: Request) -> None:
    require_pay_auth(request)
    if not _is_nwc_session_valid(request):
        raise HTTPException(status_code=401, detail="NWC unlock required")


def _pay_login_html() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="icon" href="/assets/icon.png" sizes="32x32" />
  <link rel="icon" href="/assets/icon.png" sizes="192x192" />
  <link rel="icon" href="/assets/icon.png" sizes="512x512" />
  <link rel="apple-touch-icon" href="/assets/icon.png" sizes="180x180" />
  <title>BOLT12 Pay Login</title>
  <link rel="icon" type="image/png" href="/assets/icon.png" />
  <meta http-equiv="Cache-Control" content="no-store" />
  <style>
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #0b1220;
      color: #eef2ff;
      font-family: Inter, system-ui, sans-serif;
    }}
    .card {{
      width: min(420px, calc(100vw - 32px));
      background: #111827;
      border: 1px solid #26324a;
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }}
    input {{
      width: 100%;
      box-sizing: border-box;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid #334155;
      background: #0f172a;
      color: #eef2ff;
      margin-top: 8px;
      margin-bottom: 14px;
    }}
    button {{
      width: 100%;
      padding: 12px 16px;
      border-radius: 12px;
      border: none;
      background: #f59e0b;
      color: #111827;
      font-weight: 700;
      cursor: pointer;
    }}
    .muted {{ opacity: .8; font-size: .95rem; margin-bottom: 16px; }}
    .error {{ color: #fca5a5; min-height: 24px; margin-top: 12px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <main class="card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
<a href="{HOME_URL}" aria-label="Back to homepage" title="Back to homepage" style="display:inline-flex;align-items:center;justify-content:center;text-decoration:none;">
  <img src="/assets/icon.png" alt="Logo" style="width:48px;height:48px;border-radius:12px;cursor:pointer;">
</a>
      <div>
        <div style="font-size:1.25rem;font-weight:800;">⚡ BOLT12 Pay</div>
        <div class="muted">Protected Pay Area</div>
      </div>
    </div>

    <label>Password</label>
    <input id="password" type="password" autocomplete="current-password" placeholder="Enter password" />

    <button id="loginBtn" type="button">Login</button>
    <div id="msg" class="error"></div>
  </main>

  <script>
    const loginBtn = document.getElementById("loginBtn");
    const passwordEl = document.getElementById("password");
    const msgEl = document.getElementById("msg");

    loginBtn.addEventListener("click", async () => {{
      msgEl.textContent = "";
      const payload = {{
        password: passwordEl.value || "",
        totp_code: totpEl ? (totpEl.value || "") : ""
      }};

      try {{
        const res = await fetch("/api/auth/login", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          credentials: "same-origin",
          cache: "no-store",
          body: JSON.stringify(payload)
        }});

        const data = await res.json();

        if (!res.ok) {{
          msgEl.textContent = data.detail || data.error || "Login failed";
          return;
        }}

        window.location.href = "/pay";
      }} catch (err) {{
        msgEl.textContent = "Login request failed";
      }}
    }});
  </script>
</body>
</html>"""

# --- Web files --------------------------------------------------------------
if PUBLIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=PUBLIC_DIR), name="static")


@app.get("/app")
async def app_shell(request: StarletteRequest):
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        next_url = str(request.url.path)
        if request.url.query:
            next_url += f"?{request.url.query}"
        return RedirectResponse(
            url=f"/pay-login?next={quote(next_url, safe='/?=&')}",
            status_code=307,
        )

    index_file = PUBLIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="frontend/public/index.html not found")

    resp = FileResponse(index_file)
    for k, v in _no_store_headers().items():
        resp.headers[k] = v
    return resp


@app.get("/pay")
def pay_page(request: StarletteRequest):
    if not _is_pay_ui_configured():
        return RedirectResponse(url="/app?setup=1", status_code=307)

    if not _is_pay_session_valid(request):
        next_url = str(request.url.path)
        if request.url.query:
            next_url += f"?{request.url.query}"
        return RedirectResponse(
            url=f"/pay-login?next={quote(next_url, safe='/?=&')}",
            status_code=307,
        )

    index_file = ADMIN_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="frontend/admin/index.html not found")

    resp = FileResponse(index_file)
    for k, v in _no_store_headers().items():
        resp.headers[k] = v
    return resp


@app.get("/admin")
def admin_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url="/pay", status_code=307)


@app.get("/pay-login")
def pay_login_page(request: StarletteRequest):
    if not _is_pay_ui_configured():
        return RedirectResponse(url="/app?setup=1", status_code=307)

    if _is_pay_session_valid(request):
        return RedirectResponse(url="/pay", status_code=307)

    file = ADMIN_DIR / "pay-login.html"
    if not file.exists():
        raise HTTPException(status_code=404, detail="frontend/admin/pay-login.html not found")
    resp = FileResponse(file, media_type="text/html")
    for k, v in _no_store_headers().items():
        resp.headers[k] = v
    return resp


@app.post("/api/auth/login")
def api_auth_login(payload: PayLoginRequest):
    if not _is_pay_ui_enabled():
        return JSONResponse({"ok": True, "disabled": True}, headers=_no_store_headers())

    if not _verify_ui_password(payload.password or ""):
        raise HTTPException(status_code=401, detail="Invalid password")

    token = _create_pay_session()

    resp = JSONResponse({"ok": True}, headers=_no_store_headers())
    resp.set_cookie(
        key=PAY_UI_COOKIE_NAME,
        value=token,
        max_age=PAY_UI_SESSION_TTL,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    return resp


@app.get("/api/auth/session")
def api_auth_session(request: StarletteRequest):
    configured = _is_pay_ui_configured()
    if not configured:
        return JSONResponse(
            {
                "ok": False,
                "enabled": False,
                "configured": False,
                "setup_required": True,
            },
            headers=_no_store_headers(),
        )

    ok = _is_pay_session_valid(request)
    return JSONResponse(
        {
            "ok": ok,
            "enabled": True,
            "configured": True,
            "setup_required": False,
        },
        headers=_no_store_headers(),
    )


@app.post("/api/auth/logout")
def api_auth_logout(request: StarletteRequest):
    token = _get_pay_session_token(request)
    if token:
        PAY_SESSIONS.pop(token, None)

    resp = JSONResponse({"ok": True}, headers=_no_store_headers({"Clear-Site-Data": '"cache"'}))
    resp.delete_cookie(key=PAY_UI_COOKIE_NAME, path="/")
    return resp



@app.get("/public.webmanifest")
def public_manifest() -> FileResponse:
    file = PUBLIC_DIR / "public.webmanifest"
    if not file.exists():
        raise HTTPException(status_code=404, detail="public.webmanifest not found")
    return FileResponse(file, media_type="application/manifest+json")


@app.get("/pay.webmanifest")
def pay_manifest() -> FileResponse:
    file = ADMIN_DIR / "pay.webmanifest"
    if not file.exists():
        raise HTTPException(status_code=404, detail="pay.webmanifest not found")
    return FileResponse(file, media_type="application/manifest+json")


@app.get("/admin.webmanifest")
def admin_manifest_legacy() -> RedirectResponse:
    return RedirectResponse(url="/pay.webmanifest", status_code=307)


@app.get("/service-worker.js")
def service_worker() -> FileResponse:
    file = PUBLIC_DIR / "service-worker.js"
    if not file.exists():
        raise HTTPException(status_code=404, detail="service-worker.js not found")
    resp = FileResponse(file, media_type="application/javascript")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.get("/icon.svg")
def icon_svg() -> FileResponse:
    file = PUBLIC_DIR / "icon.svg"
    if not file.exists():
        raise HTTPException(status_code=404, detail="icon.svg not found")
    return FileResponse(file, media_type="image/svg+xml")

@app.get("/{alias_name}", response_class=HTMLResponse)
async def public_alias_page(alias_name: str):
    reserved_paths = {
        "admin",
        "pay",
        "app",
        "links",
        "api",
        "favicon.ico",
        "service-worker.js",
        "public.webmanifest",
        "pay.webmanifest",
        "admin.webmanifest",
        "icon.svg",
        "static",
    }

    if alias_name in reserved_paths:
        raise HTTPException(status_code=404, detail="Not found")

    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    try:
        alias_name = _normalize_alias_name(alias_name)
    except HTTPException:
        return HTMLResponse("<h1>Alias not found</h1>", status_code=404)

    if alias_name not in aliases:
        return HTMLResponse("<h1>Alias not found</h1>", status_code=404)

    alias = aliases[alias_name]

    bip353_domain = get_bip353_base_domain()
    lnurl_domain = get_lnurl_base_domain()

    bip353_address = f"{alias_name}@{bip353_domain}"
    lnurl_address = f"{alias_name}@{lnurl_domain}"

    description = alias.get("description") or "Lightning payment"
    amount_sat = alias.get("amount_sat")
    amount_label = f"{amount_sat} sats" if amount_sat else "variable amount"

    last_offer = alias.get("last_offer") or ""

    lnurl_fallback = ""
    try:
        lnurl_info = _build_lnurl_info_for_address(lnurl_address)
        lnurl_fallback = lnurl_info["lnurl"]
    except Exception:
        lnurl_fallback = ""

    bolt11_invoice = None
    try:
        if amount_sat:
            invoice = await _create_bolt11_invoice(
                amount_sat=amount_sat,
                memo=description,
                expiry=3600,
            )
            bolt11_invoice = invoice["payment_request"] if isinstance(invoice, dict) else str(invoice)
    except Exception:
        bolt11_invoice = None

    offer_section = ""
    if last_offer:
        offer_section = f"""
        <div class="section">
          <div id="aliasOfferTitle" class="sectionTitle">BOLT12 Offer (primary)</div>
          <div class="qr">
            <img id="aliasOfferQr" class="copyable" src="/api/qr/{last_offer}" width="260" height="260" alt="BOLT12 Offer QR" title="Tap to copy QR content">
          </div>
          <div id="aliasOfferString" class="mono copyable" title="Tap to copy">{last_offer}</div>
          <div class="row">
          <button id="aliasOfferWalletBtn" onclick="window.location.href='lightning:{last_offer}'">Open with wallet</button>
          <button id="aliasCopyOfferBtn" class="secondary">Copy offer</button>
          </div>
          <div id="aliasOfferHint" class="hint">
          Primary payment method. Wallets with BOLT12 support should use this.
          </div>
        </div>
        """

    bolt11_section = ""
    if bolt11_invoice:
        bolt11_section = f"""
        <div class="section">
          <div class="sectionTitle">BOLT11 Compatibility Fallback</div>
          <div class="qr">
            <img id="aliasBolt11Qr" class="copyable" src="/api/qr/{bolt11_invoice}" width="220" height="220" alt="BOLT11 Invoice QR" title="Tap to copy QR content">
          </div>
          <div id="aliasBolt11String" class="mono copyable" title="Tap to copy">{bolt11_invoice}</div>
          <div class="row">
          <button id="aliasBolt11WalletBtn" onclick="payBolt11Invoice()">WebLN / Wallet</button>
          <button id="aliasCopyInvoiceBtn" class="secondary">Copy invoice</button>
          </div>
          <div id="aliasBolt11Hint" class="hint">
          Only for wallets without BOLT12 or LNURL support.
          </div>
        </div>
        """

    lnurl_section = ""
    if lnurl_fallback:
        lnurl_section = f"""
        <div class="section">
          <div id="aliasLnurlTitle" class="sectionTitle">LNURL Fallback</div>
          <div id="aliasLnurlString" class="mono copyable" title="Tap to copy">{lnurl_address}</div>
          <div class="qr">
            <img id="aliasLnurlQr" class="copyable" src="/api/qr/{lnurl_fallback}" width="220" height="220" alt="LNURL QR" title="Tap to copy QR content">
          </div>
          <div class="row">
          <button id="aliasCopyLnurlBtn">Copy LNURL</button>
          <button id="aliasLnurlWalletBtn" class="secondary" onclick="window.location.href='lightning:{lnurl_address}'">Open fallback with wallet</button>
          </div>
          <div id="aliasLnurlHint" class="hint">
          For wallets without BOLT12 support. QR contains the LNURL, wallet button uses Lightning Address.
         </div>
        </div>
        """

    html = f"""
<!doctype html>
<html lang="de">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="icon" href="/assets/icon.png" sizes="32x32" />
<link rel="icon" href="/assets/icon.png" sizes="192x192" />
<link rel="icon" href="/assets/icon.png" sizes="512x512" />
<link rel="apple-touch-icon" href="/assets/icon.png" sizes="180x180" />
<title>{bip353_address}</title>

<style>
body {{
  margin:0;
  font-family: system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background: linear-gradient(180deg,#0b1220,#0f172a);
  color:#eef2ff;
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:18px;
}}

.card {{
  width:100%;
  max-width:720px;
  background: rgba(18,26,43,.96);
  border:1px solid #26324a;
  border-radius:24px;
  box-shadow:0 20px 60px rgba(0,0,0,.35);
  padding:24px;
}}

h1 {{
  margin:0 0 10px;
  font-size:2rem;
  text-align:center;
}}

.sub {{
  color:#a7b0c3;
  margin-bottom:20px;
  text-align:center;
  line-height:1.5;
}}

.section {{
  margin-top:24px;
  padding-top:18px;
  border-top:1px solid #26324a;
}}

.sectionTitle {{
  font-weight:700;
  margin-bottom:12px;
}}

.qr {{
  display:flex;
  justify-content:center;
  margin:14px 0;
}}

.qr img {{
  background:white;
  padding:12px;
  border-radius:14px;
}}

.row {{
  display:flex;
  gap:10px;
  justify-content:center;
  flex-wrap:wrap;
  margin-top:10px;
}}

button {{
  appearance:none;
  border:1px solid #f7931a;
  background:#f7931a;
  color:#091120;
  font-weight:700;
  padding:12px 16px;
  border-radius:12px;
  cursor:pointer;
}}

button.secondary {{
  background:transparent;
  color:#eef2ff;
  border-color:#26324a;
}}

button:hover {{
  transform:translateY(-1px);
}}

.mono {{
  font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
  word-break:break-all;
  text-align:center;
  margin-top:6px;
}}

.copyable {{
  cursor: pointer;
}}

.copyable:hover {{
  opacity: .9;
}}

.hint {{
  color:#9aa6bd;
  font-size:.9rem;
  text-align:center;
  margin-top:8px;
}}
.toastWrap {{
  position: fixed;
  top: 14px;
  left: 50%;
  transform: translateX(-50%);
  width: min(760px, calc(100vw - 20px));
  z-index: 3000;
  pointer-events: none;
}}

.statusBar {{
  display: none;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid #26324a;
  background: #0c1322;
  font-size: .95rem;
  line-height: 1.4;
  box-shadow: 0 12px 30px rgba(0,0,0,.35);
  pointer-events: auto;
  text-align: center;
}}

.statusBar.show {{ display: block; }}

.statusBar.ok {{
  border-color: rgba(143,227,136,.35);
  background: rgba(143,227,136,.10);
  color: #8fe388;
}}

.statusBar.error {{
  border-color: rgba(255,123,114,.35);
  background: rgba(255,123,114,.10);
  color: #ff7b72;
}}

.statusBar.warn {{
  border-color: rgba(255,209,102,.35);
  background: rgba(255,209,102,.10);
  color: #ffd166;
}}
</style>
</head>

<body>
<main class="card">

  <div style="display:flex;justify-content:flex-end;margin-bottom:6px;">
    <div style="
      display:inline-flex;
      gap:4px;
      padding:4px;
      border-radius:16px;
      border:1px solid #26324a;
      background:rgba(19,28,46,.92);
    ">
      <button id="aliasLangDe"
        style="
          min-width:38px;
          height:28px;
          padding:0 8px;
          border-radius:10px;
          border:none;
          background:transparent;
          color:#a7b0c3;
          font-size:.8rem;
          font-weight:700;
        "
      >DE</button>

      <button id="aliasLangEn"
        style="
          min-width:38px;
          height:28px;
          padding:0 8px;
          border-radius:10px;
          border:none;
          background:#3a4254;
          color:#eef2ff;
          font-size:.8rem;
          font-weight:700;
        "
      >EN</button>
    </div>
  </div>
<h1 id="aliasTitle">⚡ Lightning Payment</h1>
<div style="text-align:center;margin:0 0 16px 0;">
  <a href="{HOME_URL}" aria-label="Back to homepage" title="Back to homepage" style="display:inline-flex;align-items:center;justify-content:center;text-decoration:none;">
    <img
      src="/assets/icon.png"
      alt="BOLT12 Pay Server Logo"
      style="width:64px;height:64px;object-fit:contain;display:block;margin:0 auto;cursor:pointer;filter:drop-shadow(0 0 2px rgba(255,200,0,0.30));"
    >
  </a>
</div>
<div id="aliasBip353String" class="mono copyable" title="Tap to copy">{bip353_address}</div>

<div class="sub">
<span id="aliasDescription">{description}</span><br/>
<span id="aliasAmountLabel">Amount</span>: <span id="aliasAmountValue">{amount_label}</span><br/>
<span id="aliasSubline" style="font-size:.92rem;">BOLT12 first · LNURL and BOLT11 as fallback</span>
</div>

{offer_section}

<div class="section">
<div id="aliasBip353Title" class="sectionTitle">BIP353 Address</div>
  <div class="mono">{bip353_address}</div>
  <div class="qr">
    <img id="aliasBip353Qr" class="copyable" src="/api/qr/{bip353_address}" width="220" height="220" alt="BIP353 QR" title="Tap to copy QR content">
  </div>
  <div class="row">
   <button id="aliasCopyAddressBtn">Copy address</button>
   <button id="aliasOpenWalletBtn" class="secondary" onclick="window.location.href='lightning:{bip353_address}'">Open with wallet</button>
  </div>
  <div id="aliasBip353Hint" class="hint">
  Human-readable address for this payment page.
  </div>
</div>

{lnurl_section}

{bolt11_section}
</main>

<script>
async function payBolt11Invoice() {{
  const invoice = {repr(bolt11_invoice)};

  if (!invoice) return;

  if (window.webln?.enable && window.webln?.sendPayment) {{
    try {{
      await window.webln.enable();
      await window.webln.sendPayment(invoice);
      return;
    }} catch (err) {{
      console.warn('WebLN failed, falling back to wallet link', err);
    }}
  }}

  window.location.href = 'lightning:' + invoice;
}}
</script>
<script>
(function () {{
  const T = {{
    en: {{
      title: "⚡ Lightning Payment",
      amount: "Amount",
      subline: "BOLT12 first · LNURL and BOLT11 as fallback",
      bip353Title: "BIP353 Address",
      copyAddress: "Copy address",
      openWallet: "Open with wallet",
      bip353Hint: "Human-readable address for this payment page.",
      offerTitle: "BOLT12 Offer (primary)",
      copyOffer: "Copy offer",
      offerHint: "Primary payment method. Wallets with BOLT12 support should use this.",
      lnurlTitle: "LNURL Fallback",
      copyLnurl: "Copy LNURL",
      lnurlWallet: "Open fallback with wallet",
      lnurlHint: "For wallets without BOLT12 support. QR contains the LNURL, wallet button uses Lightning Address.",
      copyInvoice: "Copy invoice",
      bolt11Hint: "Only for wallets without BOLT12 or LNURL support.",
      copiedAddress: "Address copied.",
      copiedOffer: "Offer copied.",
      copiedLnurl: "LNURL copied.",
      copiedInvoice: "Invoice copied.",
      copyFailed: "Copy failed.",
      tapToCopy: "Tap to copy",
      tapQrToCopy: "Tap to copy QR content"
    }},
    de: {{
      title: "⚡ Lightning Zahlung",
      amount: "Betrag",
      subline: "BOLT12 zuerst · LNURL und BOLT11 nur als Fallback",
      bip353Title: "BIP353 Adresse",
      copyAddress: "Adresse kopieren",
      openWallet: "Mit Wallet öffnen",
      bip353Hint: "Menschenlesbare Adresse für diese Zahlungsseite.",
      offerTitle: "BOLT12 Offer (primär)",
      copyOffer: "Offer kopieren",
      offerHint: "Primärer Zahlungsweg dieser Seite. Wallets mit BOLT12-Support sollten diesen Pfad verwenden.",
      lnurlTitle: "LNURL Fallback",
      copyLnurl: "LNURL kopieren",
      lnurlWallet: "Fallback mit Wallet öffnen",
      lnurlHint: "Für Wallets ohne BOLT12-Unterstützung. QR enthält den LNURL-String, der Wallet-Button nutzt die Lightning Address.",
      copyInvoice: "Invoice kopieren",
      bolt11Hint: "Nur für Wallets ohne BOLT12- oder LNURL-Unterstützung.",
      copiedAddress: "Adresse kopiert.",
      copiedOffer: "Offer kopiert.",
      copiedLnurl: "LNURL kopiert.",
      copiedInvoice: "Invoice kopiert.",
      copyFailed: "Kopieren fehlgeschlagen.",
      tapToCopy: "Zum Kopieren antippen",
      tapQrToCopy: "Zum Kopieren antippen (QR-Inhalt)"
    }}
  }};

  function getLang() {{
    return localStorage.getItem("app_lang") || "en";
  }}

  window.setAliasLang = function (lang) {{
    localStorage.setItem("app_lang", lang);
    applyAliasLang();
  }};

  function setActive(lang) {{
    const deBtn = document.getElementById("aliasLangDe");
    const enBtn = document.getElementById("aliasLangEn");
    if (!deBtn || !enBtn) return;

    const activeBg = "#3a4254";
    const activeColor = "#eef2ff";
    const idleBg = "transparent";
    const idleColor = "#a7b0c3";

    if (lang === "de") {{
      deBtn.style.background = activeBg;
      deBtn.style.color = activeColor;
      enBtn.style.background = idleBg;
      enBtn.style.color = idleColor;
    }} else {{
      enBtn.style.background = activeBg;
      enBtn.style.color = activeColor;
      deBtn.style.background = idleBg;
      deBtn.style.color = idleColor;
    }}
  }}

  function applyAliasTooltips() {{
    const t = T[getLang()] || T.en;
    [
      "aliasBip353String",
      "aliasOfferString",
      "aliasLnurlString",
      "aliasBolt11String"
    ].forEach((id) => {{
      const el = document.getElementById(id);
      if (el) el.title = t.tapToCopy;
    }});
    [
      "aliasBip353Qr",
      "aliasOfferQr",
      "aliasLnurlQr",
      "aliasBolt11Qr"
    ].forEach((id) => {{
      const el = document.getElementById(id);
      if (el) el.title = t.tapQrToCopy;
    }});
  }}

  function applyAliasLang() {{
    const lang = getLang();
    const t = T[lang] || T.en;

    const title = document.getElementById("aliasTitle");
    const amount = document.getElementById("aliasAmountLabel");
    const subline = document.getElementById("aliasSubline");
    const bip353Title = document.getElementById("aliasBip353Title");
    const copyAddress = document.getElementById("aliasCopyAddressBtn");
    const openWallet = document.getElementById("aliasOpenWalletBtn");
    const bip353Hint = document.getElementById("aliasBip353Hint");
    const offerTitle = document.getElementById("aliasOfferTitle");
    const copyOffer = document.getElementById("aliasCopyOfferBtn");
    const offerWallet = document.getElementById("aliasOfferWalletBtn");
    const offerHint = document.getElementById("aliasOfferHint");
    const lnurlTitle = document.getElementById("aliasLnurlTitle");
    const copyLnurl = document.getElementById("aliasCopyLnurlBtn");
    const lnurlWallet = document.getElementById("aliasLnurlWalletBtn");
    const lnurlHint = document.getElementById("aliasLnurlHint");
    const copyInvoice = document.getElementById("aliasCopyInvoiceBtn");
    const bolt11Hint = document.getElementById("aliasBolt11Hint");

    if (title) title.textContent = t.title;
    if (amount) amount.textContent = t.amount;
    if (subline) subline.textContent = t.subline;
    if (bip353Title) bip353Title.textContent = t.bip353Title;
    if (copyAddress) copyAddress.textContent = t.copyAddress;
    if (openWallet) openWallet.textContent = t.openWallet;
    if (bip353Hint) bip353Hint.textContent = t.bip353Hint;
    if (offerTitle) offerTitle.textContent = t.offerTitle;
    if (copyOffer) copyOffer.textContent = t.copyOffer;
    if (offerWallet) offerWallet.textContent = t.openWallet;
    if (offerHint) offerHint.textContent = t.offerHint;
    if (lnurlTitle) lnurlTitle.textContent = t.lnurlTitle;
    if (copyLnurl) copyLnurl.textContent = t.copyLnurl;
    if (lnurlWallet) lnurlWallet.textContent = t.lnurlWallet;
    if (lnurlHint) lnurlHint.textContent = t.lnurlHint;
    if (copyInvoice) copyInvoice.textContent = t.copyInvoice;
    if (bolt11Hint) bolt11Hint.textContent = t.bolt11Hint;

    applyAliasTooltips();
    setActive(lang);
  }}

  function showAliasToast(message, kind) {{
    const toast = document.getElementById("aliasToast");
    if (!toast) return;

    const toastKind = kind || "ok";
    toast.textContent = message || "";
    toast.className = "statusBar show " + toastKind;
    toast.style.display = "block";

    clearTimeout(window.__aliasToastTimer);
    window.__aliasToastTimer = setTimeout(() => {{
      toast.className = "statusBar";
      toast.textContent = "";
      toast.style.display = "none";
    }}, 1800);
  }}

  async function copyWithToast(text, message) {{
    const value = String(text || "").trim();
    const t = T[getLang()] || T.en;

    if (!value) {{
      showAliasToast(t.copyFailed, "error");
      return;
    }}

    try {{
      if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(value);
      }} else {{
        throw new Error("Clipboard API unavailable");
      }}
      showAliasToast(message, "ok");
      return;
    }} catch (err) {{
      try {{
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        textarea.style.pointerEvents = "none";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);

        const ok = document.execCommand("copy");
        document.body.removeChild(textarea);

        if (!ok) {{
          throw new Error("execCommand copy failed");
        }}

        showAliasToast(message, "ok");
        return;
      }} catch (fallbackErr) {{
        showAliasToast(t.copyFailed, "error");
      }}
    }}
  }}

  window.addEventListener("load", function () {{
    const deBtn = document.getElementById("aliasLangDe");
    const enBtn = document.getElementById("aliasLangEn");

    const copyAddressBtn = document.getElementById("aliasCopyAddressBtn");
    const copyOfferBtn = document.getElementById("aliasCopyOfferBtn");
    const copyLnurlBtn = document.getElementById("aliasCopyLnurlBtn");
    const copyInvoiceBtn = document.getElementById("aliasCopyInvoiceBtn");

    const bip353String = document.getElementById("aliasBip353String");
    const offerString = document.getElementById("aliasOfferString");
    const lnurlString = document.getElementById("aliasLnurlString");
    const bolt11String = document.getElementById("aliasBolt11String");

    const bip353Qr = document.getElementById("aliasBip353Qr");
    const offerQr = document.getElementById("aliasOfferQr");
    const lnurlQr = document.getElementById("aliasLnurlQr");
    const bolt11Qr = document.getElementById("aliasBolt11Qr");

    if (deBtn) deBtn.onclick = function () {{ window.setAliasLang("de"); }};
    if (enBtn) enBtn.onclick = function () {{ window.setAliasLang("en"); }};

    if (copyAddressBtn) copyAddressBtn.onclick = function () {{
      copyWithToast("{bip353_address}", (T[getLang()] || T.en).copiedAddress);
    }};
    if (copyOfferBtn) copyOfferBtn.onclick = function () {{
      copyWithToast("{last_offer}", (T[getLang()] || T.en).copiedOffer);
    }};
    if (copyLnurlBtn) copyLnurlBtn.onclick = function () {{
      copyWithToast("{lnurl_fallback}", (T[getLang()] || T.en).copiedLnurl);
    }};
    if (copyInvoiceBtn) copyInvoiceBtn.onclick = function () {{
      copyWithToast("{bolt11_invoice or ''}", (T[getLang()] || T.en).copiedInvoice);
    }};

    if (bip353String) bip353String.onclick = function () {{
      copyWithToast("{bip353_address}", (T[getLang()] || T.en).copiedAddress);
    }};
    if (offerString) offerString.onclick = function () {{
      copyWithToast("{last_offer}", (T[getLang()] || T.en).copiedOffer);
    }};
    if (lnurlString) lnurlString.onclick = function () {{
      copyWithToast("{lnurl_address}", (T[getLang()] || T.en).copiedAddress);
    }};
    if (bolt11String) bolt11String.onclick = function () {{
      copyWithToast("{bolt11_invoice or ''}", (T[getLang()] || T.en).copiedInvoice);
    }};

    if (bip353Qr) bip353Qr.onclick = function () {{
      copyWithToast("{bip353_address}", (T[getLang()] || T.en).copiedAddress);
    }};
    if (offerQr) offerQr.onclick = function () {{
      copyWithToast("{last_offer}", (T[getLang()] || T.en).copiedOffer);
    }};
    if (lnurlQr) lnurlQr.onclick = function () {{
      copyWithToast("{lnurl_fallback}", (T[getLang()] || T.en).copiedLnurl);
    }};
    if (bolt11Qr) bolt11Qr.onclick = function () {{
      copyWithToast("{bolt11_invoice or ''}", (T[getLang()] || T.en).copiedInvoice);
    }};

    applyAliasLang();
  }});
}})();
</script>
<div class="toastWrap">
  <div id="aliasToast" class="statusBar"></div>
</div>
</body>
</html>
"""
    return HTMLResponse(html)

# --- Minimal self-tests -----------------------------------------------------
def _test_extract_offer() -> None:
    sample = 'Offer: CreateOfferResponse { offer: "lno1example123" }.'
    assert _extract_offer(sample) == "lno1example123"
    assert _extract_offer("lno1justaline") == "lno1justaline"


def _test_extract_offer_from_txt_record() -> None:
    assert _extract_offer_from_txt_record("bitcoin:?lno=lno1abc") == "lno1abc"
    assert _extract_offer_from_txt_record("bitcoin:lno1abc") == "lno1abc"
    assert _extract_offer_from_txt_record("lno1abc") == "lno1abc"
    assert _extract_offer_from_txt_record("bitcoin:?something=else") is None
    assert _extract_offer_from_txt_record("bitcoin:?lno=lno1abc123") == "lno1abc123"


def _test_build_command() -> None:
    cmd = _base_command()
    assert "--grpc-host" in cmd
    assert LNDK_GRPC_HOST in cmd
    assert "--macaroon-path" in cmd
    assert "--grpc-port" in cmd


def _test_lnurl_encoding() -> None:
    encoded = _encode_lnurl(f"https://{get_lnurl_base_domain()}/.well-known/lnurlp/lnurl")
    assert encoded.startswith("lnurl1")
    assert len(encoded) > 20


def _test_alias_resolution() -> None:
    alias = _resolve_lnurl_alias("lnurl")
    assert alias["username"] == "lnurl"
    assert alias["identifier"].endswith(f"@{get_lnurl_base_domain()}")

if __name__ == "__main__":
    _test_extract_offer()
    _test_extract_offer_from_txt_record()
    _test_build_command()
    _test_lnurl_encoding()
    _test_alias_resolution()
    print("Self-tests passed.")
    print("Run with: uvicorn backend.app:app --host 0.0.0.0 --port 8081")
    print(f"ALLOW_PAY_OFFER={ALLOW_PAY_OFFER}")
    print(f"LNURL_ALIAS_MODE={LNURL_ALIAS_MODE}")
    print(f"LNURL_BASE_URL={LNURL_BASE_URL}")
    print(f"LND_REST_URL={LND_REST_URL}")
    print("Base command:")
    print(" ".join(shlex.quote(part) for part in _base_command()))
    if PUBLIC_DIR.exists():
        print(f"Serving web files from: {PUBLIC_DIR}")
    else:
        print(f"Warning: {PUBLIC_DIR} does not exist")



@app.get("/.well-known/nostr.json")
async def nostr_well_known(name: str = Query(default=None)):
    cfg = load_config()
    identity_map = cfg.get("identity_map", {}) or {}
    nostr_cfg = cfg.get("nostr", {}) or {}
    default_relays = nostr_cfg.get("default_relays", []) or []

    names = {}
    relays = {}

    def _add_alias(alias_name: str, item: dict):
        if not isinstance(item, dict):
            return
        if not item.get("nip05_enabled"):
            return

        pubkey_hex = str(item.get("nostr_pubkey") or "").strip().lower()
        if not pubkey_hex:
            return

        names[alias_name] = pubkey_hex

        alias_relays = item.get("relays") or default_relays
        if isinstance(alias_relays, list) and alias_relays:
            relays[pubkey_hex] = alias_relays

    if name:
        alias_name = name.strip().lower()
        item = identity_map.get(alias_name)
        if item:
            _add_alias(alias_name, item)
    else:
        for alias_name, item in identity_map.items():
            _add_alias(alias_name, item)

    response = {"names": names}
    if relays:
        response["relays"] = relays

    return JSONResponse(response, status_code=200)


# ===== ZAP EVENT PUBLISHING =====

import asyncio
from contextlib import suppress

import coincurve
import websockets

def _hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex((value or "").strip())

def _nostr_server_pubkey_hex() -> str:
    server_privkey = str(
        _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or _get_setting("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()
    if not server_privkey:
        return ""
    pk = coincurve.PrivateKey(_hex_to_bytes(server_privkey))
    compressed = pk.public_key.format(compressed=True).hex()
    return compressed[2:]

def _nostr_event_id_hex(event):
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    raw = json.dumps(payload, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()

def _normalize_nostr_private_key(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""

    raw_lower = raw.lower()

    if raw_lower.startswith("nsec1"):
        try:
            hrp, data = bech32.bech32_decode(raw_lower)
            if hrp != "nsec" or data is None:
                return ""
            decoded = bech32.convertbits(data, 5, 8, False)
            if decoded is None:
                return ""
            return bytes(decoded).hex()
        except Exception:
            return ""

    try:
        if len(raw_lower) == 64:
            bytes.fromhex(raw_lower)
            return raw_lower
    except Exception:
        return ""

    return ""


def _notification_signing_privkey_hex() -> str:
    notify_nsec = str(
        _get_secret("NOSTR_NOTIFY_NSEC", "nostr_notify_nsec", default="")
        or ""
    ).strip()
    if notify_nsec:
        return _normalize_nostr_private_key(notify_nsec)

    server_privkey = str(
        _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or _get_setting("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()
    if server_privkey:
        return _normalize_nostr_private_key(server_privkey)

    return ""


def _sign_nostr_event_with_privkey(event: dict[str, Any], privkey_hex: str) -> dict[str, Any]:
    event = dict(event)
    privkey = coincurve.PrivateKey(_hex_to_bytes(privkey_hex))
    pubkey_hex = privkey.public_key_xonly.format().hex()

    event["pubkey"] = pubkey_hex
    serialized = json.dumps(
        [0, pubkey_hex, event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    sig = privkey.sign_schnorr(bytes.fromhex(event_id), aux_randomness=b"\x00" * 32).hex()

    event["id"] = event_id
    event["sig"] = sig
    return event

def _sign_nostr_event(event):
    event = dict(event)
    event["pubkey"] = _nostr_server_pubkey_hex()
    event["id"] = _nostr_event_id_hex(event)

    server_privkey = str(
        _get_secret("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or _get_setting("NOSTR_SERVER_PRIVKEY", "nostr_server_privkey", default="")
        or ""
    ).strip().lower()
    if not server_privkey:
        raise ValueError("No nostr server private key configured")
    privkey = coincurve.PrivateKey(_hex_to_bytes(server_privkey))
    sig = privkey.sign_schnorr(bytes.fromhex(event["id"]), aux_randomness=b"\x00"*32)
    event["sig"] = sig.hex()
    return event

def _nip04_encrypt(privkey_hex: str, pubkey_hex: str, plaintext: str) -> str:
    privkey_bytes = bytes.fromhex(privkey_hex)
    recipient_pubkey = PublicKey(bytes.fromhex("02" + pubkey_hex))

    shared_point = recipient_pubkey.multiply(privkey_bytes)
    shared_point_compressed = shared_point.format(compressed=True)

    key = shared_point_compressed[1:33]

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), 16))

    return (
        base64.b64encode(encrypted).decode("ascii")
        + "?iv="
        + base64.b64encode(iv).decode("ascii")
    )



def _nip04_decrypt(privkey_hex: str, pubkey_hex: str, payload: str) -> str:
    try:
        if "?iv=" not in payload:
            raise ValueError("Missing ?iv= separator")

        ciphertext_b64, iv_b64 = payload.split("?iv=", 1)
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        privkey_bytes = bytes.fromhex(privkey_hex)
        sender_pubkey = PublicKey(bytes.fromhex("02" + pubkey_hex))

        shared_point = sender_pubkey.multiply(privkey_bytes)
        shared_point_compressed = shared_point.format(compressed=True)

        key = shared_point_compressed[1:33]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), 16)

        return decrypted.decode("utf-8")

    except Exception as exc:
        raise ValueError(f"NIP-04 decrypt failed: {exc}") from exc


def _build_dm_event(recipient_pubkey_hex: str, encrypted_content: str) -> dict[str, Any]:
    return {
        "kind": 4,
        "created_at": int(time.time()),
        "tags": [["p", recipient_pubkey_hex]],
        "content": encrypted_content,
    }

def _nostr_encode_bech32(hrp: str, raw: bytes) -> str:
    data = bech32.convertbits(list(raw), 8, 5, True)
    if data is None:
        raise ValueError("bech32 convertbits failed")
    return bech32.bech32_encode(hrp, data)

def _build_zap_dm_message(item: dict[str, Any]) -> str:
    sats = int(item.get("amount_msat") or 0) // 1000
    identifier = item.get("identifier") or "your address"
    comment = (item.get("comment") or "").strip()
    payer_hex = (item.get("payer_pubkey_hex") or "").strip()
    zap_request_event = item.get("zap_request_event") or {}

    payer_display = "someone"
    if payer_hex:
        try:
            payer_display = "@" + _nostr_encode_bech32("npub", bytes.fromhex(payer_hex))
        except Exception:
            payer_display = payer_hex[:12] + "…"

    note_event_id = ""
    for tag in zap_request_event.get("tags") or []:
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "e":
            note_event_id = str(tag[1]).strip()
            if note_event_id:
                break

    is_profile_zap = not bool(note_event_id)

    note_ref = ""
    if note_event_id:
        try:
            note_ref = "nostr:" + _nostr_encode_bech32("note", bytes.fromhex(note_event_id))
        except Exception:
            note_ref = note_event_id

    lines = []

    if is_profile_zap:
        line = f"Received Profile Zap from {payer_display} with amount: {sats} sats ⚡"
        if comment:
            line += f" for Comment: {comment}"
        return line

    lines.append(f"Received Zap from {payer_display} with amount: {sats} sats ⚡ for note:")

    if note_ref:
        lines.append(note_ref)
    else:
        lines.append(identifier)

    if comment:
        lines.append("")
        lines.append(f"Comment: {comment}")

    return "\n".join(lines)

async def _publish_nostr_event_to_relay(relay_url, event):
    try:
        async with websockets.connect(relay_url) as ws:
            await ws.send(json.dumps(["EVENT", event]))
            return {"relay": relay_url, "ok": True}
    except Exception as e:
        return {"relay": relay_url, "ok": False, "error": str(e)}

async def _publish_nostr_event(relays, event):
    return await asyncio.gather(*[
        _publish_nostr_event_to_relay(r, event) for r in relays
    ])


def _build_notification_event(item, settled_invoice):
    amount_msat = int(item.get("amount_msat") or 0)
    amount_sat = amount_msat // 1000 if amount_msat else 0
    comment = (item.get("comment") or "").strip()
    identifier = item.get("identifier") or "your address"
    is_zap = bool(item.get("is_zap"))

    if is_zap and comment:
        content = f"⚡ Zap received on {identifier}: {amount_sat} sats • {comment}"
    elif is_zap:
        content = f"⚡ Zap received on {identifier}: {amount_sat} sats"
    else:
        content = f"⚡ Lightning payment received on {identifier}: {amount_sat} sats"

    tags = [
        ["p", item["recipient_pubkey_hex"]],
    ]

    payer = item.get("payer_pubkey_hex")
    if payer:
        tags.append(["P", payer])

    if amount_msat:
        tags.append(["amount", str(amount_msat)])

    if comment:
        tags.append(["comment", comment])

    return {
        "kind": 1,
        "created_at": int(time.time()),
        "tags": tags,
        "content": content,
    }

def _normalize_relays(relays):
    out = []
    seen = set()

    for relay in relays or []:
        parts = str(relay).replace("\r", "").split("\n")
        for part in parts:
            value = part.strip()
            if not value:
                continue
            if not value.startswith("wss://"):
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append(value)

    return out


def _get_pending_zaps():
    cfg = load_config()
    data = cfg.get("pending_zaps", {}) or {}

    changed = False
    for item in data.values():
        if isinstance(item, dict):
            cleaned = _normalize_relays(item.get("relays", []))
            if cleaned != item.get("relays", []):
                item["relays"] = cleaned
                changed = True

    if changed:
        cfg["pending_zaps"] = data
        save_config(cfg)

    return data

def _save_pending_zaps(data):
    cfg = load_config()
    cfg["pending_zaps"] = data
    save_config(cfg)

import base64


async def _lookup_invoice(payment_hash):
    macaroon_hex = _read_macaroon_hex(LND_MACAROON_PATH)
    headers = {"Grpc-Metadata-macaroon": macaroon_hex}

    # --- FIX: Base64 → HEX ---
    try:
        raw = base64.b64decode(payment_hash)
        payment_hash_hex = raw.hex()
    except Exception:
        payment_hash_hex = payment_hash  # fallback (alte Einträge)
    # -------------------------

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        r = await client.get(
            f"{LND_REST_URL}/v1/invoice/{payment_hash_hex}",
            headers=headers
        )
        return r.json()

async def _process_pending_zaps_once():
    pending = _get_pending_zaps()

    for k, item in list(pending.items()):
        if item.get("published"):
            continue

        inv = await _lookup_invoice(k)
        if not inv.get("settled"):
            continue

        zap_request = item.get("zap_request_event") or {}

        tags = [
            ["p", item["recipient_pubkey_hex"]],
            ["bolt11", item["payment_request"]],
            ["description", json.dumps(zap_request, separators=(",", ":"), ensure_ascii=False)],
        ]

        payer_pubkey = item.get("payer_pubkey_hex")
        if payer_pubkey:
            tags.append(["P", payer_pubkey])

        for t in zap_request.get("tags", []):
            if isinstance(t, list) and len(t) >= 2 and t[0] in {"e", "a"}:
                tags.append(t)

        if item.get("amount_msat"):
            tags.append(["amount", str(item["amount_msat"])])

        preimage = inv.get("r_preimage") or inv.get("payment_preimage") or ""
        if preimage:
            tags.append(["preimage", preimage])

        event = {
            "kind": 9735,
            "created_at": int(time.time()),
            "tags": tags,
            "content": "",
        }

        signed = _sign_nostr_event(event)
        relays = item.get("relays") or NOSTR_DEFAULT_RELAYS

        result = await _publish_nostr_event(relays, signed)

        try:
            dm_message = _build_zap_dm_message(item)
            notify_privkey_hex = _notification_signing_privkey_hex()
            if not notify_privkey_hex:
                raise ValueError("No notification signing key configured")

            encrypted_dm = _nip04_encrypt(
                notify_privkey_hex,
                item["recipient_pubkey_hex"],
                dm_message,
            )
            dm_event = _build_dm_event(item["recipient_pubkey_hex"], encrypted_dm)
            notify_privkey_hex = _notification_signing_privkey_hex()
            if not notify_privkey_hex:
                raise ValueError("No notification signing key configured")
            signed_dm = _sign_nostr_event_with_privkey(dm_event, notify_privkey_hex)
            dm_result = await _publish_nostr_event(relays, signed_dm)
            item["dm_event"] = signed_dm
            item["dm_result"] = dm_result
        except Exception as exc:
            item["dm_error"] = str(exc)

        item["published"] = True
        item["result"] = result
        pending[k] = item
    _save_pending_zaps(pending)

async def _zap_publisher_loop():
    while True:
        try:
            await _process_pending_zaps_once()
        except Exception as e:
            print("zap loop error", e, flush=True)
        await asyncio.sleep(NOSTR_ZAP_POLL_INTERVAL)

@app.on_event("startup")
async def startup_background_tasks():
    app.state.zap_task = asyncio.create_task(_zap_publisher_loop())
    app.state.nwc_task = asyncio.create_task(start_nwc_runtime())
    print("zap publisher loop started", flush=True)
    print("[NWC] startup task scheduled", flush=True)

@app.get("/api/admin/nostr-status")
async def api_admin_nostr_status(request: StarletteRequest):
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    return _get_nostr_admin_status()



def load_secrets() -> dict:
    path = Path("/data/config/secrets.json")
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_secrets(data: dict) -> None:
    path = Path("/data/config/secrets.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")



@app.post("/api/admin/nostr-notify-key")
async def api_admin_nostr_notify_key(request: StarletteRequest):
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    data = await request.json()
    nsec = str(data.get("notify_nsec") or "").strip()

    if not nsec:
        raise HTTPException(status_code=400, detail="notify_nsec is required")

    try:
        _normalize_nsec_to_hex(nsec)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid nsec")

    secrets = load_secrets()
    secrets["nostr_notify_nsec"] = nsec
    save_secrets(secrets)
    return {"ok": True, "status": _get_nostr_admin_status()}


@app.post("/api/admin/nostr-server-key/generate")
async def api_admin_nostr_server_key_generate(request: StarletteRequest):
    if _is_pay_ui_enabled() and not _is_pay_session_valid(request):
        raise HTTPException(status_code=401, detail="Authentication required")

    privkey_hex = _generate_nostr_private_key_hex()
    cfg = load_config()
    cfg["nostr_server_privkey"] = privkey_hex
    save_config(cfg)

    return {"ok": True, "status": _get_nostr_admin_status()}

@app.get("/api/debug/pending-zaps")
def debug_zaps():
    return _get_pending_zaps()



@app.post("/api/admin/nwc/unlock")
async def api_admin_nwc_unlock(payload: NwcUnlockRequest, request: StarletteRequest):
    require_pay_auth(request)

    password = (payload.password or "").strip()
    if not password:
        raise HTTPException(status_code=401, detail="Password required")

    configured_hash = _get_ui_password_hash()
    if not configured_hash:
        raise HTTPException(status_code=400, detail="No Pay UI password configured")

    if _hash_password(password) != configured_hash:
        raise HTTPException(status_code=401, detail="Invalid password")

    token, expires_at = _issue_nwc_session()
    resp = JSONResponse({
        "ok": True,
        "expires_in": max(0, expires_at - int(time.time()))
    })
    resp.set_cookie(
        key=NWC_COOKIE_NAME,
        value=token,
        max_age=NWC_SESSION_TTL,
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
    )
    return resp


@app.post("/api/admin/nwc/lock")
async def api_admin_nwc_lock(request: StarletteRequest):
    require_pay_auth(request)

    token = _read_nwc_session_token(request)
    if token:
        NWC_SESSIONS.pop(token, None)

    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=NWC_COOKIE_NAME, path="/")
    return resp

def _augment_nwc_budget_info(item: dict[str, Any]) -> dict[str, Any]:
    limits = item.get("limits") or {}
    usage = item.get("usage") or {}

    budget_limit_sat = int(limits.get("budget_amount_sat") or 0)
    budget_spent_sat = int(usage.get("spent_sat") or 0)
    budget_remaining_sat = max(budget_limit_sat - budget_spent_sat, 0) if budget_limit_sat > 0 else None

    item["budget_limit_sat"] = budget_limit_sat
    item["budget_spent_sat"] = budget_spent_sat
    item["budget_remaining_sat"] = budget_remaining_sat

    return item

@app.get("/api/admin/nwc/connections")
async def api_admin_nwc_connections(request: StarletteRequest):
    require_pay_auth(request)
    require_nwc_auth(request)

    items = list_nwc_connections()
    out = []
    for item in items:
        item_copy = dict(item)
        item_copy = _augment_nwc_budget_info(item_copy)
        item_copy["uri"] = build_nwc_uri(item_copy)
        item_copy["client_secret_masked"] = (
            item_copy.get("client_secret", "")[:8] + "…" if item_copy.get("client_secret") else ""
        )
        out.append(item_copy)
    return {"connections": out}


@app.post("/api/admin/nwc/connections")
async def api_admin_nwc_connections_create(
    payload: NwcConnectionCreateRequest,
    request: StarletteRequest,
):
    require_pay_auth(request)
    require_nwc_auth(request)

    wallet_service_pubkey = _nostr_server_pubkey_hex()
    if not wallet_service_pubkey:
        raise HTTPException(
            status_code=400,
            detail="No Nostr server private key configured. Generate the server key first.",
        )

    item = create_nwc_connection(
    wallet_service_pubkey=wallet_service_pubkey,
    name=payload.name,
    relay_url=payload.relay_url,
    allow_get_info=payload.allow_get_info,
    allow_get_balance=payload.allow_get_balance,
    allow_pay_invoice=payload.allow_pay_invoice,
    max_payment_sat=payload.max_payment_sat,
    budget_period=payload.budget_period,
    budget_amount_sat=payload.budget_amount_sat,
)
    await reload_nwc_runtime()
    return {"ok": True, "connection": {
        **item,
        "uri": build_nwc_uri(item),
        "limits": item.get("limits", {
        "max_payment_sat": 1000,
        "budget_period": "none",
        "budget_amount_sat": 0,
    })
    }}


@app.post("/api/admin/nwc/connections/{connection_id}/toggle")
async def api_admin_nwc_connections_toggle(connection_id: str, request: StarletteRequest):
    require_pay_auth(request)
    require_nwc_auth(request)

    try:
        item = toggle_nwc_connection(connection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="NWC connection not found")

    await reload_nwc_runtime()
    return {"ok": True, "connection": {
        **item,
        "uri": build_nwc_uri(item),
        "limits": item.get("limits", {
            "max_payment_sat": 1000,
            "daily_budget_sat": 5000
        })
    }}


@app.delete("/api/admin/nwc/connections/{connection_id}")
async def api_admin_nwc_connections_delete(connection_id: str, request: StarletteRequest):
    require_pay_auth(request)
    require_nwc_auth(request)

    try:
        delete_nwc_connection(connection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="NWC connection not found")

    await reload_nwc_runtime()
    return {"ok": True}

# ===== END ZAP EVENTS =====


from .nwc_runtime import start_nwc_runtime, reload_nwc_runtime
