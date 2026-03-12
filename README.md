# BOLT12 Pay

Self-hosted Lightning payment server combining:

- BOLT12 Offers (primary payment flow)
- LNURL-Pay fallback (BOLT11 invoices)
- BIP353 Lightning addresses
- FastAPI backend + static frontend
- Designed for Umbrel / self-hosted nodes

---

# Deployment modes

## Local development

Use a local bind mount for secrets.

Environment variables:

```
LNDK_CERT_PATH=/secrets/tls.cert
LNDK_MACAROON_PATH=/secrets/admin.macaroon
LND_TLS_CERT_PATH=/secrets/tls.cert
LND_MACAROON_PATH=/secrets/admin.macaroon
```

Mount secrets directory:

```yaml
volumes:
  - ./secrets:/secrets:ro
```

---

## Umbrel deployment

Use the external Umbrel/LNDK secrets volume.

Important: the BOLT12/LNDK path and LNURL/LND REST path may use different certificate files.

```
LNDK_CERT_PATH=/secrets/lndk-tls-cert.pem
LNDK_MACAROON_PATH=/secrets/admin.macaroon

LND_TLS_CERT_PATH=/secrets/tls.cert
LND_MACAROON_PATH=/secrets/admin.macaroon
```

This is expected:

- BOLT12 offers are created via lndk-cli
- LNURL fallback creates BOLT11 invoices via LND REST

---

# Current working deployment

This repository contains a working self-hosted BOLT12 payment setup built around:

- lndk running on Umbrel / Portainer
- bolt12-pay FastAPI backend
- static frontend UI
- Cloudflare Tunnel for public access
- Cloudflare Access protecting admin endpoints
- LNURL fallback server
- BIP353 Lightning addresses

---

# Public endpoints

```
/
.well-known/lnurlp/<username>
```

---

# Protected endpoints

```
/admin
/api/create-offer
/api/pay-offer
/api/decode-offer
```

These should be protected by Cloudflare Access or another reverse proxy.

---

# Persistent Docker volumes

## lndk_lndk_data

Persistent data volume for the lndk container.

## lndk_secrets

Shared secrets volume used by:

- lndk
- bolt12-pay

Required files:

```
tls.cert
admin.macaroon
lndk-tls-cert.pem
```

---

# Portainer stack files

Saved stack definitions:

```
deploy/portainer-lndk.yml
deploy/portainer-bolt12-pay.yml
```

---

# Umbrel reboot note

After Umbrel reboots, lndk may start before Lightning is ready.

Use:

```
scripts/wait-for-lnd.sh
```

This script waits for:

- /secrets/tls.cert
- /secrets/admin.macaroon
- LND gRPC 192.168.188.39:10009

before starting lndk.

---

# Security note

Never commit:

- TLS certificates
- macaroons
- .env files
- secrets directories
