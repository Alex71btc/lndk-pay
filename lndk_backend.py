from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


# --- Configuration ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

LNDK_CLI = os.environ.get("LNDK_CLI", "lndk-cli")
LNDK_NETWORK = os.environ.get("LNDK_NETWORK", "bitcoin")
LNDK_GRPC_HOST = os.environ.get("LNDK_GRPC_HOST", "https://YOUR_NODE_IP")
LNDK_GRPC_PORT = os.environ.get("LNDK_GRPC_PORT", "7000")
LNDK_CERT_PATH = os.environ.get("LNDK_CERT_PATH", str(Path.home() / "lndk-tls-cert.pem"))
LNDK_MACAROON_PATH = os.environ.get("LNDK_MACAROON_PATH", str(Path.home() / "admin.macaroon"))
REQUEST_TIMEOUT = float(os.environ.get("LNDK_TIMEOUT_SECONDS", "30"))
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
ALLOW_PAY_OFFER = os.environ.get("ALLOW_PAY_OFFER", "false").lower() in {"1", "true", "yes", "on"}

# Extract the lno... offer string from lndk-cli output like:
# Offer: CreateOfferResponse { offer: "lno1..." }.
OFFER_RE = re.compile(
    r'offer:\s*CreateOfferResponse\s*\{\s*offer:\s*"(?P<offer>lno[^"\s]+)"',
    re.IGNORECASE,
)


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
    offer: str = Field(min_length=4)
    amount_sat: int = Field(ge=1, description="Amount to pay in sats")
    payer_note: Optional[str] = Field(default=None, max_length=300)


class PayOfferResponse(BaseModel):
    raw_output: str


class HealthResponse(BaseModel):
    ok: bool
    cli: str
    grpc_host: str
    grpc_port: str
    cert_path: str
    macaroon_path: str


app = FastAPI(title="LNDK Backend", version="0.1.0")

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


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        ok=True,
        cli=LNDK_CLI,
        grpc_host=LNDK_GRPC_HOST,
        grpc_port=LNDK_GRPC_PORT,
        cert_path=LNDK_CERT_PATH,
        macaroon_path=LNDK_MACAROON_PATH,
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
    args = _base_command() + ["decode-offer", payload.offer]
    raw_output = _run_command(args)
    return DecodeResponse(raw_output=raw_output)


@app.post("/api/pay-offer", response_model=PayOfferResponse)
def pay_offer(payload: PayOfferRequest) -> PayOfferResponse:
    if not ALLOW_PAY_OFFER:
        raise HTTPException(status_code=403, detail="pay-offer endpoint is disabled")

    args = _base_command() + ["pay-offer", payload.offer, str(payload.amount_sat * 1000)]
    if payload.payer_note:
        args.append(payload.payer_note)

    raw_output = _run_command(args)
    return PayOfferResponse(raw_output=raw_output)


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="web/index.html not found")
    return FileResponse(index_file)


# --- Minimal self-tests ----------------------------------------------------
def _test_extract_offer() -> None:
    sample = 'Offer: CreateOfferResponse { offer: "lno1example123" }.'
    assert _extract_offer(sample) == "lno1example123"
    assert _extract_offer("lno1justaline") == "lno1justaline"


def _test_build_command() -> None:
    cmd = _base_command()
    assert "--grpc-host" in cmd
    assert LNDK_GRPC_HOST in cmd
    assert "--macaroon-path" in cmd
    assert "--grpc-port" in cmd


if __name__ == "__main__":
    _test_extract_offer()
    _test_build_command()
    print("Self-tests passed.")
    print("Run with: uvicorn lndk_backend:app --host 0.0.0.0 --port 8081")
    print(f"ALLOW_PAY_OFFER={ALLOW_PAY_OFFER}")
    print("Base command:")
    print(" ".join(shlex.quote(part) for part in _base_command()))
    if WEB_DIR.exists():
        print(f"Serving web files from: {WEB_DIR}")
    else:
        print(f"Warning: {WEB_DIR} does not exist")
