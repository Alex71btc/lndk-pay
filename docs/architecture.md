# BOLT12 Pay Architecture

## Overview

The project combines two separate Lightning payment flows in one app:

1. BOLT12 primary flow
2. LNURL fallback flow

## Payment paths

### BOLT12 primary flow

- frontend calls backend
- backend uses `lndk-cli`
- `lndk-cli` talks to LNDK over gRPC
- LNDK talks to LND

Relevant paths:

- `LNDK_CERT_PATH=/secrets/lndk-tls-cert.pem` on Umbrel
- `LNDK_MACAROON_PATH=/secrets/admin.macaroon`

### LNURL fallback flow

- wallet calls `/.well-known/lnurlp/<username>`
- wallet calls `/api/lnurl/callback/<username>?amount=...`
- backend creates a BOLT11 invoice over LND REST
- wallet pays BOLT11 invoice

Relevant paths:

- `LND_TLS_CERT_PATH=/secrets/tls.cert`
- `LND_MACAROON_PATH=/secrets/admin.macaroon`

## DNS / BIP353 modes

The app should support three modes:

### Basic mode

- BOLT12 works
- LNURL works
- no DNS automation

### Manual DNS mode

- app shows the TXT record name and value
- user sets the BIP353 record manually at their DNS provider

### Cloudflare mode

- app stores Cloudflare credentials
- app creates TXT records automatically

## Config direction

Long-term app settings should move from environment variables into:

`/data/config.json`

This allows:

- first-run setup wizard
- optional Cloudflare integration
- setup restart from admin UI
- easier Umbrel app UX

## Goal

Umbrel Community App with:

- public BOLT12 pay page
- LNURL fallback
- optional BIP353 DNS automation
- admin UI
- self-hosted Lightning identity/payment endpoint
