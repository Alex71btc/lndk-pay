from __future__ import annotations

import json
import math
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import dns.exception
import dns.resolver
import httpx
import qrcode
from io import BytesIO
from fastapi.responses import FileResponse, Response, HTMLResponse
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.config import load_config, save_config

# --- Configuration ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
PUBLIC_DIR = PROJECT_ROOT / "frontend" / "public"
ADMIN_DIR = PROJECT_ROOT / "frontend" / "admin"

LNDK_CLI = os.environ.get("LNDK_CLI", "lndk-cli")
LNDK_NETWORK = os.environ.get("LNDK_NETWORK", "bitcoin")
LNDK_GRPC_HOST = os.environ.get("LNDK_GRPC_HOST", "https://192.168.188.39")
LNDK_GRPC_PORT = os.environ.get("LNDK_GRPC_PORT", "7000")
LNDK_CERT_PATH = os.environ.get("LNDK_CERT_PATH", str(Path.home() / "lndk-tls-cert.pem"))
LNDK_MACAROON_PATH = os.environ.get("LNDK_MACAROON_PATH", str(Path.home() / "admin.macaroon"))
REQUEST_TIMEOUT = float(os.environ.get("LNDK_TIMEOUT_SECONDS", "30"))
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
ALLOW_PAY_OFFER = os.environ.get("ALLOW_PAY_OFFER", "false").lower() in {"1", "true", "yes", "on"}

def get_public_bolt12_address():
    cfg = load_config()
    return cfg.get("public_bolt12_address") or os.environ.get("PUBLIC_BIP353_ADDRESS", "bolt12@pay.local")

def get_public_lnurl_address():
    cfg = load_config()
    return cfg.get("public_lnurl_address") or os.environ.get("PUBLIC_LNURL_ADDRESS", "lnurl@pay.local")

DNS_RESOLVER_LIFETIME = float(os.environ.get("DNS_RESOLVER_LIFETIME", "10"))
DNS_RESOLVER_TIMEOUT = float(os.environ.get("DNS_RESOLVER_TIMEOUT", "10"))

LNURL_BASE_DOMAIN = os.environ.get("LNURL_BASE_DOMAIN", "pay.alex71btc.com").strip().lower()
LNURL_BASE_URL = os.environ.get("LNURL_BASE_URL", f"https://{LNURL_BASE_DOMAIN}").strip().rstrip("/")
LNURL_MIN_SENDABLE_MSAT = int(os.environ.get("LNURL_MIN_SENDABLE_MSAT", "1000"))
LNURL_MAX_SENDABLE_MSAT = int(os.environ.get("LNURL_MAX_SENDABLE_MSAT", "1000000000"))
LNURL_COMMENT_ALLOWED = int(os.environ.get("LNURL_COMMENT_ALLOWED", "120"))
LNURL_ALIAS_MODE = os.environ.get("LNURL_ALIAS_MODE", "shared").strip().lower()
LNURL_SHARED_DESCRIPTION = os.environ.get(
    "LNURL_SHARED_DESCRIPTION",
    f"LNURL payment via {LNURL_BASE_DOMAIN}",
).strip()
LNURL_DEFAULT_DESCRIPTION = os.environ.get("LNURL_DEFAULT_DESCRIPTION", "Lightning payment").strip()
LNURL_ALIAS_MAP_RAW = os.environ.get("LNURL_ALIAS_MAP", "").strip()
LND_REST_INSECURE = os.environ.get("LND_REST_INSECURE", "false").lower() in {"1", "true", "yes", "on"}
LND_REST_URL = os.environ.get("LND_REST_URL", "https://192.168.188.39:8080").strip().rstrip("/")
LND_TLS_CERT_PATH = os.environ.get("LND_TLS_CERT_PATH", "/secrets/tls.cert").strip()
LND_MACAROON_PATH = os.environ.get("LND_MACAROON_PATH", "/secrets/admin.macaroon").strip()
LND_REST_TIMEOUT = float(os.environ.get("LND_REST_TIMEOUT_SECONDS", "30"))


# Extract the lno... offer string from lndk-cli output like:
# Offer: CreateOfferResponse { offer: "lno1..." }.
OFFER_RE = re.compile(
    r'offer:\s*CreateOfferResponse\s*\{\s*offer:\s*"(?P<offer>lno[^"\s]+)"',
    re.IGNORECASE,
)

HRN_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LNURL_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


# --- Models ----------------------------------------------------------------
class OfferRequest(BaseModel):
    amount: Optional[int] = Field(
        default=None,
        ge=1,
        description="Minimum amount in sats. If omitted, backend uses 1 sat.",
    )
    description: str = Field(default="bolt12@alex71btc.com", min_length=1, max_length=200)
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


class PayOfferRequest(BaseModel):
    offer: str = Field(
        min_length=4,
        description="Either an lno... offer or a BIP353 human-readable address",
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
    allowsNostr: bool = False


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

# --- App -------------------------------------------------------------------
app = FastAPI(title="LNDK Backend", version="0.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

def get_cloudflare_config():
    cfg = load_config()
    cf = cfg.get("cloudflare", {}) or {}

    return {
        "enabled": bool(cf.get("enabled")),
        "zone_name": str(cf.get("zone_name", "")).strip(),
        "zone_id": str(cf.get("zone_id", "")).strip(),
        "api_token": str(cf.get("api_token", "")).strip(),
    }

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


def _lightning_address_to_lnurlp_url(address: str) -> str:
    clean = address.strip().lower()
    if not HRN_RE.match(clean):
        raise HTTPException(status_code=400, detail="Invalid lightning address format")
    user, domain = clean.split("@", 1)
    return f"https://{domain}/.well-known/lnurlp/{user}"


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

def _lnurl_metadata_json(identifier: str, description: str) -> str:
    return json.dumps(
        [
            ["text/plain", description],
            ["text/identifier", identifier],
        ],
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


def _lnurl_callback_url(username: str) -> str:
    return f"{get_lnurl_base_url()}/api/lnurl/callback/{username}"

def get_lnurl_base_domain():
    cfg = load_config()
    return cfg.get("lnurl_base_domain") or os.environ.get("LNURL_BASE_DOMAIN", "pay.alex71btc.com")


def get_lnurl_base_url():
    cfg = load_config()
    return cfg.get("lnurl_base_url") or os.environ.get("LNURL_BASE_URL", f"https://{get_lnurl_base_domain()}").rstrip("/")

def _read_macaroon_hex(path: str) -> str:
    try:
        return Path(path).read_bytes().hex()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"macaroon file not found: {path}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"failed to read macaroon file: {exc}") from exc
def get_lnurl_base_domain():
    cfg = load_config()
    return (cfg.get("lnurl_base_domain") or os.environ.get("LNURL_BASE_DOMAIN", "pay.alex71btc.com")).strip().lower()


def get_lnurl_base_url():
    cfg = load_config()
    return (cfg.get("lnurl_base_url") or os.environ.get(
        "LNURL_BASE_URL",
        f"https://{get_lnurl_base_domain()}",
    )).strip().rstrip("/")

async def _create_bolt11_invoice(*, amount_sat: int, memo: str, expiry: int = 3600) -> dict[str, Any]:
    macaroon_hex = _read_macaroon_hex(LND_MACAROON_PATH)

    headers = {
        "Grpc-Metadata-macaroon": macaroon_hex,
        "Content-Type": "application/json",
    }

    payload = {
        "value": str(amount_sat),
        "memo": memo,
        "expiry": str(expiry),
    }

    verify = False if LND_REST_INSECURE else LND_TLS_CERT_PATH

    try:
        async with httpx.AsyncClient(timeout=LND_REST_TIMEOUT, verify=verify) as client:
            response = await client.post(
                f"{LND_REST_URL}/v1/invoices",
                headers=headers,
                json=payload,
            )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LND REST request failed: {exc}") from exc

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
    }

def get_public_bolt12_address():
    cfg = load_config()
    return cfg.get("public_bolt12_address") or os.environ.get("PUBLIC_BIP353_ADDRESS", "bolt12@pay.local")


def get_public_lnurl_address():
    cfg = load_config()
    return cfg.get("public_lnurl_address") or os.environ.get("PUBLIC_LNURL_ADDRESS", "lnurl@pay.local")


def get_cloudflare_config():
    cfg = load_config()
    cf = cfg.get("cloudflare", {}) or {}

    return {
        "enabled": bool(cf.get("enabled")),
        "zone_name": str(cf.get("zone_name", "")).strip(),
        "zone_id": str(cf.get("zone_id", "")).strip(),
        "api_token": str(cf.get("api_token", "")).strip(),
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
    )


@app.get("/api/lnurl/callback/{username}")
async def lnurl_callback(
    username: str,
    amount: int = Query(..., ge=1, description="Requested amount in millisatoshis"),
    comment: Optional[str] = Query(default=None),
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

    amount_sat = max(1, math.ceil(amount / 1000))
    memo = alias["identifier"]
    if comment:
        memo = f"{memo} | {comment[:120]}"

    payment_request = await _create_bolt11_invoice(
        amount_sat=amount_sat,
        memo=memo,
    )

    return {
        "pr": payment_request,
        "routes": [],
        "successAction": {
            "tag": "message",
            "message": f"Payment request for {alias['identifier']}",
        },
        "disposable": False,
    }

@app.get("/api/setup/status")
def setup_status():

    cfg = load_config()

    configured = bool(cfg.get("lnurl_base_domain"))

    return {
        "configured": configured
    }

@app.get("/api/setup/config")
def get_setup_config():
    return load_config()

@app.post("/api/setup/config")
def set_setup_config(payload: dict):

    cfg = load_config()

    cfg.update(payload)

    save_config(cfg)

    return {
        "ok": True
    }

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


@app.post("/api/cloudflare/create-bip353")
async def create_cloudflare_bip353(req: CloudflareBIP353Request):
    record_name = req.record_name.strip().lower()
    if not record_name:
        raise HTTPException(status_code=400, detail="record_name required")

    txt_name = _alias_dns_name(record_name)
    txt_value = build_bip353_txt_value(req.offer)

    result = await _cloudflare_upsert_txt_record(name=txt_name, content=txt_value)

    return {
        "ok": True,
        "name": txt_name,
        "content": txt_value,
        "result": result,
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

@app.post("/api/create-invoice", response_model=CreateInvoiceResponse)
async def create_invoice(payload: CreateInvoiceRequest) -> CreateInvoiceResponse:
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
@app.get("/{alias_name}", response_class=HTMLResponse)
async def public_alias_page(alias_name: str):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    try:
        alias_name = _normalize_alias_name(alias_name)
    except HTTPException:
        return HTMLResponse("<h1>Alias not found</h1>", status_code=404)

    if alias_name not in aliases:
        return HTMLResponse("<h1>Alias not found</h1>", status_code=404)

    alias = aliases[alias_name]
    address = f"{alias_name}@{get_lnurl_base_domain()}"
    description = alias.get("description") or "Lightning payment"
    amount_sat = alias.get("amount_sat")
    amount_label = f"{amount_sat} sats" if amount_sat else "variabler Betrag"

    html = f"""
<!doctype html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{address}</title>
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
      max-width: 560px;
      background: rgba(18, 26, 43, 0.96);
      border: 1px solid #26324a;
      border-radius: 24px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, .35);
      padding: 24px;
      text-align: center;
    }}
    .pill {{
      display: inline-block;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(247, 147, 26, 0.12);
      border: 1px solid rgba(247, 147, 26, 0.3);
      color: #ffd9a3;
      font-size: .95rem;
      margin-bottom: 16px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 1.8rem;
    }}
    .sub {{
      color: #a7b0c3;
      margin-bottom: 18px;
      line-height: 1.5;
    }}
    .qr {{
      background: white;
      padding: 18px;
      border-radius: 18px;
      display: inline-block;
      margin: 18px 0;
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      word-break: break-all;
    }}
    .row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: center;
      margin-top: 16px;
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
    .hint {{
      margin-top: 14px;
      color: #a7b0c3;
      font-size: .92rem;
      line-height: 1.5;
    }}
  </style>
</head>
<body>
  <main class="card">
    <div class="pill">Lightning Alias</div>
    <h1>{address}</h1>
    <div class="sub">{description}<br />Betrag: {amount_label}</div>

    <div class="qr">
      <img src="/api/qr/{address}" width="260" height="260" alt="QR Code">
    </div>

    <div class="mono">{address}</div>

    <div class="row">
      <button onclick="window.location.href='lightning:{address}'">Mit Wallet öffnen</button>
      <button class="secondary" onclick="navigator.clipboard.writeText('{address}')">Adresse kopieren</button>
    </div>

    <div class="row">
      <button class="secondary" onclick="createBolt11()">BOLT11 Rechnung erzeugen</button>
    </div>

    <div id="invoiceWrap" style="display:none; margin-top:18px;">
      <div class="qr">
        <img id="invoiceQr" src="" width="260" height="260" alt="Invoice QR">
      </div>
      <div id="invoiceText" class="mono"></div>
      <div class="row">
        <button onclick="payInvoice()">Mit Alby / WebLN bezahlen</button>
        <button class="secondary" onclick="copyInvoice()">Rechnung kopieren</button>
      </div>
    </div>

    <div class="hint">
      Diese Seite nutzt standardmäßig die Lightning Address. Optional kann eine normale BOLT11-Rechnung erzeugt werden.
    </div>
  </main>

  <script>
    let currentInvoice = "";

    async function createBolt11() {{
      try {{
        const response = await fetch('/api/create-invoice', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            amount_sat: {amount_sat or 21000},
            memo: {description!r},
            expiry: 3600
          }})
        }});

        const data = await response.json();
        if (!response.ok) {{
          throw new Error(data?.detail || 'Invoice creation failed');
        }}

        currentInvoice = data.payment_request;
        document.getElementById('invoiceText').textContent = currentInvoice;
        document.getElementById('invoiceQr').src = '/api/qr/' + encodeURIComponent(currentInvoice);
        document.getElementById('invoiceWrap').style.display = 'block';
      }} catch (err) {{
        alert('Fehler: ' + (err?.message || err));
      }}
    }}

    async function payInvoice() {{
      if (!currentInvoice) return;

      if (window.webln?.enable && window.webln?.sendPayment) {{
        try {{
          await window.webln.enable();
          await window.webln.sendPayment(currentInvoice);
          return;
        }} catch (err) {{
          console.warn(err);
        }}
      }}

      window.location.href = 'lightning:' + currentInvoice;
    }}

    async function copyInvoice() {{
      if (!currentInvoice) return;
      await navigator.clipboard.writeText(currentInvoice);
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(html)

@app.get("/{alias_name}", response_class=HTMLResponse)
async def public_alias_page(alias_name: str):
    cfg = load_config()
    aliases = cfg.get("aliases", {}) or {}

    alias_name = _normalize_alias_name(alias_name)

    if alias_name not in aliases:
        return HTMLResponse("<h1>Alias not found</h1>", status_code=404)

    alias = aliases[alias_name]

    address = f"{alias_name}@{get_lnurl_base_domain()}"
    description = alias.get("description") or "Lightning payment"

    html = f"""
    <html>
    <head>
        <title>{address}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: sans-serif;
                background:#0f1115;
                color:#fff;
                text-align:center;
                padding:40px;
            }}
            .box {{
                max-width:500px;
                margin:auto;
                background:#1a1f2b;
                padding:30px;
                border-radius:12px;
            }}
            button {{
                padding:12px 18px;
                margin-top:20px;
                border:none;
                border-radius:8px;
                background:#ff7a18;
                color:white;
                font-size:16px;
                cursor:pointer;
            }}
        </style>
    </head>
    <body>
        <div class="box">
            <h2>{address}</h2>
            <p>{description}</p>

            <p>Scan or pay with Lightning</p>

            <img src="/api/qr/{address}" width="260"/>

            <br>

            <button onclick="window.location.href='lightning:{address}'">
                Pay with Lightning
            </button>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(html)
# --- Web files --------------------------------------------------------------
if PUBLIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=PUBLIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    index_file = PUBLIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="frontend/public/index.html not found")
    return FileResponse(index_file)


@app.get("/admin")
def admin_page() -> FileResponse:
    index_file = ADMIN_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="frontend/admin/index.html not found")
    return FileResponse(index_file)


@app.get("/public.webmanifest")
def public_manifest() -> FileResponse:
    file = PUBLIC_DIR / "public.webmanifest"
    if not file.exists():
        raise HTTPException(status_code=404, detail="public.webmanifest not found")
    return FileResponse(file, media_type="application/manifest+json")


@app.get("/admin.webmanifest")
def admin_manifest() -> FileResponse:
    file = ADMIN_DIR / "admin.webmanifest"
    if not file.exists():
        raise HTTPException(status_code=404, detail="admin.webmanifest not found")
    return FileResponse(file, media_type="application/manifest+json")


@app.get("/service-worker.js")
def service_worker() -> FileResponse:
    file = PUBLIC_DIR / "service-worker.js"
    if not file.exists():
        raise HTTPException(status_code=404, detail="service-worker.js not found")
    return FileResponse(file, media_type="application/javascript")


@app.get("/icon.svg")
def icon_svg() -> FileResponse:
    file = PUBLIC_DIR / "icon.svg"
    if not file.exists():
        raise HTTPException(status_code=404, detail="icon.svg not found")
    return FileResponse(file, media_type="image/svg+xml")


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
