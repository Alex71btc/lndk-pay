from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import dns.resolver
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


# --- Configuration ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
PUBLIC_DIR = PROJECT_ROOT / "frontend" / "public"
ADMIN_DIR = PROJECT_ROOT / "frontend" / "admin"

LNDK_CLI = os.environ.get("LNDK_CLI", "lndk-cli")
LNDK_NETWORK = os.environ.get("LNDK_NETWORK", "bitcoin")
LNDK_GRPC_HOST = os.environ.get("LNDK_GRPC_HOST", "https://YOUR_NODE_IP")
LNDK_GRPC_PORT = os.environ.get("LNDK_GRPC_PORT", "7000")
LNDK_CERT_PATH = os.environ.get("LNDK_CERT_PATH", str(Path.home() / "lndk-tls-cert.pem"))
LNDK_MACAROON_PATH = os.environ.get("LNDK_MACAROON_PATH", str(Path.home() / "admin.macaroon"))
REQUEST_TIMEOUT = float(os.environ.get("LNDK_TIMEOUT_SECONDS", "30"))
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
ALLOW_PAY_OFFER = os.environ.get("ALLOW_PAY_OFFER", "false").lower() in {"1", "true", "yes", "on"}
DNS_RESOLVER_LIFETIME = float(os.environ.get("DNS_RESOLVER_LIFETIME", "5"))

# Extract the lno... offer string from lndk-cli output like:
# Offer: CreateOfferResponse { offer: "lno1..." }.
OFFER_RE = re.compile(
    r'offer:\s*CreateOfferResponse\s*\{\s*offer:\s*"(?P<offer>lno[^"\s]+)"',
    re.IGNORECASE,
)
HRN_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class OfferRequest(BaseModel):
    amount: Optional[int] = Field(default=None, ge=1, description="Minimum amount in sats. If omitted, backend uses 1 sat.")
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
    offer: str = Field(min_length=4, description="Either an lno... offer or a BIP353 human-readable address")
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


app = FastAPI(title="LNDK Backend", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def _resolve_bip353_address(address: str) -> str:
    if not HRN_RE.match(address):
        raise HTTPException(status_code=400, detail="Invalid human-readable address format")

    user, domain = address.split("@", 1)
    candidate_fqdns = [
        f"{user}._bitcoin-payment.{domain}",
        f"{user}.user._bitcoin-payment.{domain}",
    ]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_RESOLVER_LIFETIME
    last_lookup_error: Optional[Exception] = None

    for fqdn in candidate_fqdns:
        try:
            answers = resolver.resolve(fqdn, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            last_lookup_error = exc
            continue
        except dns.exception.Timeout as exc:
            raise HTTPException(status_code=504, detail=f"DNS lookup timed out for {address}") from exc

        for answer in answers:
            txt_value = "".join(part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in answer.strings)
            offer = _extract_offer_from_txt_record(txt_value)
            if offer:
                return offer

    if last_lookup_error is not None:
        raise HTTPException(
            status_code=404,
            detail=f"No BIP353 TXT record found for {address}. Tried: {', '.join(candidate_fqdns)}",
        ) from last_lookup_error

    raise HTTPException(
        status_code=422,
        detail=f"TXT records for {address} did not contain a usable lno offer. Tried: {', '.join(candidate_fqdns)}",
    )


def _normalize_offer_or_hrn(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("lno"):
        return candidate
    if HRN_RE.match(candidate):
        return _resolve_bip353_address(candidate)
    raise HTTPException(status_code=400, detail="Value must be either an lno... offer or a user@domain BIP353 address")


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


@app.post("/api/create-offer", response_model=OfferResponse)
def create_offer(payload: OfferRequest) -> OfferResponse:
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

# --- Minimal self-tests ----------------------------------------------------
def _test_extract_offer() -> None:
    sample = 'Offer: CreateOfferResponse { offer: "lno1example123" }.'
    assert _extract_offer(sample) == "lno1example123"
    assert _extract_offer("lno1justaline") == "lno1justaline"


def _test_extract_offer_from_txt_record() -> None:
    assert _extract_offer_from_txt_record('bitcoin:?lno=lno1abc') == 'lno1abc'
    assert _extract_offer_from_txt_record('bitcoin:lno1abc') == 'lno1abc'
    assert _extract_offer_from_txt_record('lno1abc') == 'lno1abc'
    assert _extract_offer_from_txt_record('bitcoin:?something=else') is None


def _test_build_command() -> None:
    cmd = _base_command()
    assert "--grpc-host" in cmd
    assert LNDK_GRPC_HOST in cmd
    assert "--macaroon-path" in cmd
    assert "--grpc-port" in cmd


if __name__ == "__main__":
    _test_extract_offer()
    _test_extract_offer_from_txt_record()
    _test_build_command()
    print("Self-tests passed.")
    print("Run with: uvicorn backend.app:app --host 0.0.0.0 --port 8081")
    print(f"ALLOW_PAY_OFFER={ALLOW_PAY_OFFER}")
    print("Base command:")
    print(" ".join(shlex.quote(part) for part in _base_command()))
    if PUBLIC_DIR.exists():
        print(f"Serving web files from: {PUBLIC_DIR}")
    else:
        print(f"Warning: {PUBLIC_DIR} does not exist")
