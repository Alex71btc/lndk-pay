# ⚡ BOLT12 Pay

Self-hosted Lightning payment and identity server with next-generation BOLT12 support.

---

## ✨ Features

- ⚡ BOLT12 Offers (create & pay)
- 🔗 Lightning Address (BIP353)
- 🔄 LNURL fallback
- 🧾 BOLT11 fallback invoices
- 🧠 Nostr identity (NIP-05 + Zaps)
- 📱 QR-based payments
- ☁️ Optional Cloudflare DNS automation
- 🌐 Automatic Cloudflare DNS provisioning for BIP353 and LNURL
- 🟢 Available in the official Start9 Community Registry

---

## ⚠️ Requirement: BOLT12-enabled Lightning node

BOLT12 Pay requires a Lightning node with BOLT12 support.

---

## Official app availability

BOLT12 Pay is officially available on:

- Umbrel App Store
- StartOS Community Registry / Marketplace

---

# 🟣 Umbrel Setup (Manual LND Config REQUIRED)

BOLT12 requires onion messaging support in LND.

This must be enabled manually.

## Step 1 — Edit LND config

Open Umbrel → Files and navigate to:

```text
Apps → lightning → data → lnd → lnd.conf
```

## Step 2 — Add this

```text
[protocol]
protocol.custom-message=513
protocol.custom-nodeann=39
protocol.custom-init=39
```

## Step 3 — Restart Lightning Node app

⚠️ Without this, BOLT12 will NOT work.

## Step 4 — Install BOLT12 Pay

From the official App Store, search for `BOLT12 Pay`.

Repository:

https://github.com/getumbrel/umbrel-apps/tree/master/bolt12-pay

⚠️ If you use Cloudflare automation, enter your root domain (for example `yourdomain.com`) as the Cloudflare Zone Domain, not a subdomain.

## Umbrel + Cloudflare Tunnel note

When exposing BOLT12 Pay on Umbrel through Cloudflare Tunnel, route your public domain to:

```text
http://umbrel.local:8367
```

In Cloudflare Tunnel HTTP settings, set:

```text
HTTP Host Header: umbrel.local
```

This helps Umbrel route authenticated app access correctly.

Important limitation:

Umbrel authentication may redirect authenticated app routes back to:

```text
http://umbrel.local:8367
```

Public payment/discovery endpoints remain usable over the public HTTPS domain, but browser features that require a secure HTTPS context, such as QR camera scanning or PWA installation, may only work reliably when the page remains on the public HTTPS origin.

For best public payment functionality, use the public domain for LNURL, BIP353 and public payment endpoints.

---

# 🟢 StartOS Setup (Recommended)

BOLT12 Pay is available in the official Start9 Community Registry ⚡

Features:

- one-click installation
- StartOS 0.4 support
- integrated LNDK runtime
- BOLT12 Offers
- Lightning Address support
- LNURL fallback

## Install from Community Registry

Inside StartOS:

1. Open Marketplace
2. Switch to Community Registry
3. Search for `BOLT12 Pay`
4. Install 🎉

Repository:

https://github.com/Start9-Community/bolt12-pay-startos

## Requirements

- official StartOS LND package
- onion messaging enabled

## Install LND

https://github.com/Start9Labs/lnd-startos/releases

## Remote Access (recommended)

Recommended:

- Cloudflare Tunnel
- Cloudflare Access for admin protection

Public payment endpoints must remain reachable.

---

# 🌐 Domain Configuration (BIP353 vs LNURL)

Many setup issues are caused by confusion between:

- Cloudflare Zone Domain
- BIP353 (Lightning Address) Domain
- LNURL Domain

---

## Recommended Setup (Simple)

BOLT12 Pay can serve both BIP353 and LNURL from the same domain.

For most users this is the recommended configuration:

```text
Cloudflare Zone:
yourdomain.com

BOLT12 Address:
bolt12@yourdomain.com

LNURL Address:
sats@yourdomain.com

LNURL Base Domain:
yourdomain.com

LNURL Base URL:
https://yourdomain.com
```

Advantages:

- simpler setup
- cleaner Lightning addresses
- fewer DNS records
- easier Cloudflare configuration
- less maintenance

---

## Optional: Dedicated LNURL Subdomain

Advanced users may choose to host LNURL on a separate subdomain:

```text
Cloudflare Zone:
yourdomain.com

BOLT12 Address:
bolt12@yourdomain.com

LNURL Address:
sats@pay.yourdomain.com

LNURL Base Domain:
pay.yourdomain.com

LNURL Base URL:
https://pay.yourdomain.com
```

Reasons to use a dedicated subdomain:

- separate branding
- separate infrastructure
- advanced routing setups
- compatibility testing

This setup is optional and not required.

---

## Cloudflare Zone Domain

When configuring Cloudflare automation, the Zone Domain must always be your root domain.

Correct:

```text
yourdomain.com
```

Incorrect:

```text
pay.yourdomain.com
```

The Cloudflare Zone is the parent domain that contains all DNS records.

---

## Real-world Example

```text
Cloudflare Zone:
alex71btc.com

BOLT12 Address:
bolt12@alex71btc.com

LNURL Address:
sats@alex71btc.com

LNURL Base Domain:
alex71btc.com

LNURL Base URL:
https://alex71btc.com
```

---

## Common Mistakes

❌ Cloudflare Zone = pay.yourdomain.com

✅ Cloudflare Zone = yourdomain.com

---

❌ LNURL Base URL = http://yourdomain.com

✅ LNURL Base URL = https://yourdomain.com

---

✅ Using the same domain for BIP353 and LNURL is fully supported

✅ A dedicated LNURL subdomain is optional

---

# 🔒 Access Control

Admin:

- `/pay`
- `/pay-login`

Public:

- LNURL
- payment callbacks
- public pages

---

# 🧱 Architecture

- LNDK → BOLT12 Offers
- LND → Lightning backend
- LNURL / BIP353 → compatibility
- Nostr → identity + zaps
- Web UI → admin + payments

---

# 📸 StartOS Community Marketplace

BOLT12 Pay is available in the Start9 Community Registry.

---

# 🧾 License

MIT
