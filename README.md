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
- 🟢 Available in the official Start9 Community Registry

---

## ⚠️ Requirement: BOLT12-enabled Lightning node

BOLT12 Pay requires a Lightning node with BOLT12 support.

---

# 🟣 Umbrel Setup (Manual LND Config REQUIRED)

BOLT12 requires onion messaging support in LND.

This must be enabled manually.

## Step 1 — Connect to Umbrel

```bash
ssh umbrel@umbrel.local
```

## Step 2 — Edit LND config

```bash
nano ~/umbrel/app-data/lightning/data/lnd/lnd.conf
```

## Step 3 — Add this

```text
[protocol]
protocol.custom-message=513
protocol.custom-nodeann=39
protocol.custom-init=39
```

## Step 4 — Restart Lightning

```bash
sudo reboot
```

⚠️ Without this, BOLT12 will NOT work.

## Step 5 — Install BOLT12 Pay

👉 https://github.com/Alex71btc/umbrel-community-store

---

# 🟢 StartOS Setup (Recommended)

BOLT12 Pay is now available in the official Start9 Community Registry ⚡

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
👉 https://github.com/Start9-Community/bolt12-pay-startos

## Requirements

- official Startos LND package 
- onion messaging enabled

## Install LND 

https://github.com/Start9Labs/lnd-startos/releases

## Remote Access (recommended)

Recommended:
- Cloudflare Tunnel
- Cloudflare Access for admin protection

Public payment endpoints must remain reachable.

---

# 🔒 Access control

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
- Nostr → identity + Zaps
- Web UI → admin + payments

---

# 📸 StartOS Community Marketplace

BOLT12 Pay is now officially available in the Start9 Community Registry.

---

# 🧾 License

MIT
