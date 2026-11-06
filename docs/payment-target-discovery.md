# Payment target discovery

BOLT12 Pay exposes a small, versioned JSON document so wallets, agents and
other automated clients do not have to infer the supported payment method from
a page or QR image.

This is a BOLT12 Pay extension, not a BOLT, BIP, LNURL specification or NIP.
Clients should check `schema` and `version` and ignore unknown fields.

## Endpoint

```http
GET /.well-known/bolt12-pay/<alias>
Accept: application/json
```

The endpoint is public because it describes an already public payment target.
Responses may be cached for 60 seconds. A missing or disabled alias returns the
same error used by the corresponding LNURL alias lookup.

The LNURL-pay metadata for the same alias includes `bolt12PayDiscovery` with
the discovery URL. Older LNURL clients safely ignore this additional field.

## Version 1 example

```json
{
  "schema": "bolt12-pay/payment-target-discovery",
  "version": 1,
  "identifier": "alice@example.com",
  "description": "Tips for Alice",
  "addresses": {
    "lightning": "alice@example.com",
    "bip353": "alice@example.com"
  },
  "methods": [
    {
      "type": "bolt12_offer",
      "reusable": true,
      "offer": "lno1...",
      "amount": {
        "fixed_msat": null,
        "min_msat": 1000,
        "max_msat": null
      },
      "payer_note": {
        "supported": true,
        "max_chars": null
      },
      "zap": { "supported": false }
    },
    {
      "type": "lightning_address",
      "reusable": true,
      "address": "alice@example.com",
      "resolves_to": "lnurl_pay",
      "amount": {
        "fixed_msat": null,
        "min_msat": 1000,
        "max_msat": 1000000000
      },
      "comment": { "supported": true, "max_chars": 120 },
      "zap": { "supported": true, "nostr_pubkey": "..." }
    },
    {
      "type": "lnurl_pay",
      "reusable": true,
      "endpoint": "https://pay.example.com/.well-known/lnurlp/alice",
      "amount": {
        "fixed_msat": null,
        "min_msat": 1000,
        "max_msat": 1000000000
      },
      "comment": { "supported": true, "max_chars": 120 },
      "zap": { "supported": true, "nostr_pubkey": "..." }
    }
  ],
  "qr": {
    "primary": { "type": "bolt12_offer", "value": "lno1..." },
    "bolt11_fallback": {
      "type": "bolt11_invoice",
      "reusable": false,
      "generated_on_demand": true,
      "endpoint": "/api/alias/alice/bolt11-fallback"
    }
  }
}
```

Unavailable values are `null`; unavailable methods are omitted from `methods`.
`fixed_msat`, `min_msat` and `max_msat` are always millisatoshis when present.
A `bolt11_fallback` is an invoice creation endpoint, not a reusable invoice.

## QR type signal

The QR PNG endpoint returns an `X-BOLT12-Pay-QR-Type` response header. HTML QR
containers and server-rendered QR images expose the same value through
`data-payment-type`.

Version 1 type values are:

- `bolt12_offer`
- `bolt12_invoice`
- `bolt12_invoice_request`
- `bolt11_invoice`
- `lnurl`
- `payment_address`
- `unknown`

The visible badge remains the primary signal for people. The header and data
attribute are the stable signal for software.

## Security properties

Discovery is read-only and grants no authentication or payment authority. It
does not expose LND credentials, NWC secrets, Companion tokens, payment history,
memos or payer notes, and it does not make outbound requests. Alias names must
be supplied explicitly; there is no listing endpoint. The response deliberately
omits the running server version to reduce unnecessary fingerprinting.

The advertised BOLT11 fallback already exists on the public alias page. Invoice
creation is protected by both a per-client/per-alias limit and a separate global
per-alias limit, so a forged forwarding header cannot bypass all throttling.
Operators may change those limits with
`PUBLIC_ALIAS_INVOICE_RATE_LIMIT_MAX_REQUESTS` and
`PUBLIC_ALIAS_INVOICE_GLOBAL_RATE_LIMIT_MAX_REQUESTS`.
