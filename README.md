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

---

## ⚠️ Requirement: BOLT12-enabled Lightning node

BOLT12 Pay requires a Lightning node with BOLT12 support.

---

# 🟣 Umbrel Setup (Manual LND Config REQUIRED)

BOLT12 requires **onion messaging support in LND**.

This must be enabled manually.

---

## Step 1 — Connect to Umbrel

```bash
ssh umbrel@umbrel.local
```

---

## Step 2 — Edit LND config

```bash
nano ~/umbrel/app-data/lightning/data/lnd/lnd.conf
```

---

## Step 3 — Add this

```text
[protocol]
custom-message=513
custom-nodeann=39
custom-init=39
```

---

## Step 4 — Restart Lightning

```bash
sudo reboot
```

⚠️ Without this, BOLT12 will NOT work.

---

## Step 5 — Install BOLT12 Pay

BOLT12 Pay is available for Umbrel via my community store:

👉 https://github.com/Alex71btc/umbrel-community-store

1. Install from Umbrel Community Store  
2. Open app  
3. Complete setup  
4. Done 🎉

---

# 🟢 Start9 Setup (Recommended)

Start9 uses a dedicated BOLT12-enabled LND.

⚠️ Important:
- Both Start9 packages are currently distributed via GitHub Releases only
- They are **not available in the official Start9 Marketplace**
- Installation currently requires **manual sideloading**
- Install and use at your own risk
- Always create a backup before upgrading or migrating

---

## Install LND BOLT12

Repository:
👉 https://github.com/Alex71btc/lnd-startos-bolt12

Releases:
👉 https://github.com/Alex71btc/lnd-startos-bolt12/releases

- App name: **LND BOLT12**
- Package ID: `lndbolt`

---

## Optional: Import existing LND

Inside Start9 UI:

- Open **LND BOLT12**
- Actions → **Import from Start9 LND**

⚠️ Never run two LND nodes with the same wallet state at the same time.

---

## Install BOLT12 Pay

Repository:
👉 https://github.com/Alex71btc/bolt12-pay-start9

Releases:
👉 https://github.com/Alex71btc/bolt12-pay-start9/releases

1. Install BOLT12 Pay  
2. Open app  
3. Configure:
   - BOLT12 address
   - Lightning address
   - domain / DNS  

---

# 🌐 Remote Access (recommended)

Use:

👉 https://github.com/remcoros/cloudflared-startos/releases

---

# 🔒 Access control (IMPORTANT)

BOLT12 Pay separates:

## Admin (sensitive)

- `/pay`
- `/pay-login`

## Public (must stay open)

- LNURL
- payment callbacks
- public pages

---

## Recommended (Cloudflare Access)

### 1. Admin → ALLOW

Protect:

- `/pay*`
- `/pay-login*`

Require login.

---

### 2. Public → BYPASS

Allow:

- LNURL
- payment endpoints
- public pages

---

## ⚠️ Do NOT

- protect the whole app → breaks payments  
- expose `/pay` publicly → security risk  

---

# 🧱 Architecture

BOLT12 Pay combines:

- **LNDK** → BOLT12 Offers
- **LND** → Lightning backend
- **LNURL / BIP353** → compatibility
- **Nostr** → identity + Zaps
- **Web UI** → admin + payments

---

# 🧠 Capabilities

## Payment pages

- BOLT12 Offer
- Lightning Address
- LNURL fallback
- BOLT11 fallback

---

## Admin UI

- create offers
- pay offers
- decode BOLT12 / BIP353
- manage aliases
- Nostr integration

---

# 🧪 Status

BOLT12 Pay is cutting-edge:

- BOLT12 still evolving
- wallet support inconsistent
- fallback layers required

---

# 🧰 Deployment

- `deploy/docker-compose.local.yml`
- `deploy/docker-compose.umbrel.yml`

---

# 📂 Structure

- `app/`
- `umbrel/`
- `start9/`
- `docs/`

---

# 🧾 License

MIT

---

# 💡 Funding

This project is a strong candidate for Bitcoin / Lightning open-source grants.

Feel free to contribute or reach out.
